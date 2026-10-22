// SPDX-License-Identifier: BSD-2-Clause-Patent
// Native UFS bring-up (erhai SM8750 copy of the sheng SM8550 driver). Default-off: no MMIO is touched unless
// native-ufs-probe=1 is present. This is a register probe, not a storage driver.
#include <IOKit/IOService.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <libkern/crypto/sha2.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <sys/param.h>
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
#include "verified_root.h"
#include "VerifiedBlockPolicy.h"
extern "C" {
extern const struct vr_crypto vr_xnu_crypto;
extern const uint8_t verified_root_key[];
}
#endif
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSIterator.h>
#include <IOKit/IOBSD.h>
#include <kern/thread.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>
#include <kern/debug.h>
#include "GccUfs.h"
#include "RootDiagnostics.h"
#include "TransferPoll.h"
#include "SmmuTakeover.h"

static UfsRootDiagnostics gRootDiagnostic;
static bool gRootDiagnosticEnabled;
static void rootDiagnosticFailure (const char *reason);

extern "C" {
// Optional passive observer; absent in ordinary builds. It may run while a
// window lock is held, so its contract forbids blocking or transport access.
void boot_progress_poll (void) __attribute__((weak));
volatile uint32_t native_ufs_probe_calls = 0;
volatile uint32_t native_ufs_matched = 0;
volatile uint32_t native_ufs_probe_requested = 0;
volatile uint32_t native_ufs_mapped = 0;
volatile uint32_t native_ufs_status = 0;
// Root start: 1 entered, 2 host up, 3 layout found; the last soft-failure reason (a static string), for the boot page.
volatile uint32_t native_ufs_root_step = 0;
const char *volatile native_ufs_root_failure = nullptr;
volatile uint32_t native_ufs_cap = 0;
volatile uint32_t native_ufs_version = 0;
volatile uint32_t native_ufs_hcs = 0;
volatile uint32_t native_ufs_hce = 0;
volatile uint32_t native_ufs_utrl_ready = 0;
volatile uint32_t native_ufs_uic_status = 0;
volatile uint32_t native_ufs_uic_result = 0;
}

class NativeUfs : public IOService {
  OSDeclareDefaultStructors (NativeUfs)
  OSSharedPtr<IOMemoryMap> fMap;
  OSSharedPtr<IOBufferMemoryDescriptor> fCmdDesc;
  void inspect (void);
  void adoptAndRead (unsigned level);
  void dumpFirmwareList (void);
  void inspectSmmu (void);
  void inspectContextBanks (void);
  void dumpSmmuStreams (void);
  void dumpUicState (bool hibernateExit);
  bool startRoot (IOService *provider);
  static bool waitSet (uintptr_t base, unsigned offset, uint32_t mask, unsigned loops);
public:
  IOService *probe (IOService *provider, SInt32 *score) override;
  bool start (IOService *provider) override;
  void stop (IOService *provider) override;
};

OSDefineMetaClassAndStructors (NativeUfs, IOService)

static uint32_t read32 (uintptr_t base, unsigned offset)
{
  return *reinterpret_cast<volatile uint32_t *> (base + offset);
}

static void write32 (uintptr_t base, unsigned offset, uint32_t value)
{
  *reinterpret_cast<volatile uint32_t *> (base + offset) = value;
}

static bool contains (const char *data, size_t length, const char *needle)
{
  size_t wanted = 0;
  while (needle[wanted]) {
    wanted++;
  }
  for (size_t at = 0; at + wanted <= length; at++) {
    size_t index = 0;
    while (index < wanted && data[at + index] == needle[index]) {
      index++;
    }
    if (index == wanted) {
      return true;
    }
  }
  return false;
}

IOService *NativeUfs::probe (IOService *provider, SInt32 *score)
{
  native_ufs_probe_calls = native_ufs_probe_calls + 1;
  if (OSDynamicCast (IOPlatformExpertDevice, provider)) {
    // Second personality (KernelConfigTables: IOMatchCategory NativeUfsRoot): attaches to the
    // root device, which starts before the platform expert publishes IOResources, so the
    // hardware probes run before the original AMFI (whose start panics without a PMGR).
    native_ufs_matched = 1;
    if (score) {
      *score = 500;
    }
    return this;
  }
  OSObject *property = provider->getProperty ("compatible");
  OSData *data = OSDynamicCast (OSData, property);
  OSString *string = OSDynamicCast (OSString, property);
  bool match = false;
  if (data) {
    const char *text = static_cast<const char *> (data->getBytesNoCopy ());
    match = text && contains (text, data->getLength (), "qcom,sm8750-ufshc");
  } else if (string) {
    const char *text = string->getCStringNoCopy ();
    match = text && contains (text, string->getLength (), "qcom,sm8750-ufshc");
  }
  if (!match) {
    return nullptr;
  }
  native_ufs_matched = 1;
  if (score) {
    *score = 1000;
  }
  return this;
}

bool NativeUfs::waitSet (uintptr_t base, unsigned offset, uint32_t mask, unsigned loops)
{
  for (unsigned index = 0; index < loops; index++) {
    if ((read32 (base, offset) & mask) == mask) {
      return true;
    }
    IODelay (1);
  }
  return false;
}

// Read-only inspection (native-ufs-probe=2): reports what firmware left behind.
// The physical windows are the sheng board DT's own GCC (0x100000) and UFS host
// (0x1d84000, 0x3000) ranges. The controller is read only if the GCC says its
// GDSC is powered and the AXI/AHB branches are running; nothing is written.
static uintptr_t mapPhys (uint64_t phys, uint64_t length, OSSharedPtr<IOMemoryMap> &keep)
{
  IODeviceMemory *memory = IODeviceMemory::withRange (phys, length);
  if (!memory) {
    return 0;
  }
  keep = OSSharedPtr<IOMemoryMap> (memory->map (kIOMapAnywhere | kIOMapInhibitCache), OSNoRetain);
  memory->release ();
  return keep ? static_cast<uintptr_t> (keep->getVirtualAddress ()) : 0;
}

void NativeUfs::inspect (void)
{
  OSSharedPtr<IOMemoryMap> gccMap, memPhyMap, hcMap;
  uintptr_t gcc = mapPhys (GCC_BASE + 0x77000, 0x1000, gccMap);
  uintptr_t memPhy = mapPhys (GCC_BASE + 0x9e000, 0x1000, memPhyMap);
  if (!gcc || !memPhy) {
    panic ("NATIVE_UFS inspect: GCC map failed gcc=%p memphy=%p", (void *) gcc, (void *) memPhy);
  }
  uint32_t gdsc = read32 (gcc, GCC_UFS_PHY_GDSCR - 0x77000);
  uint32_t axi = read32 (gcc, GCC_UFS_PHY_AXI_ENABLE - 0x77000);
  uint32_t ahb = read32 (gcc, GCC_UFS_PHY_AHB_ENABLE - 0x77000);
  uint32_t unipro = read32 (gcc, GCC_UFS_PHY_UNIPRO_CORE_ENABLE - 0x77000);
  uint32_t txs = read32 (gcc, GCC_UFS_PHY_TX_SYMBOL0_ENABLE - 0x77000);
  uint32_t rxs = read32 (gcc, GCC_UFS_PHY_RX_SYMBOL0_ENABLE - 0x77000);
  uint32_t aux = read32 (gcc, GCC_UFS_PHY_PHY_AUX_ENABLE - 0x77000);
  uint32_t memGdsc = read32 (memPhy, 0);
  // GDSCR bit31 PWR_ON; CBCR bit31 CLK_OFF.
  bool powered = (gdsc & 0x80000000U) != 0;
  // Hardware 2026-10-17: AXI running, AHB enabled but CLK_OFF (bit31). With bit1 (HW gating)
  // set the branch wakes on access, so enable bits, not CLK_OFF, gate the read-only probe.
  bool busClocks = !(axi & 0x80000000U) && (ahb & 0x1U) && (axi & 0x1U);
  uint32_t cap = 0, ver = 0, hcs = 0, hce = 0, utrlba = 0, is = 0;
  unsigned readHc = 0;
  if (powered && busClocks) {
    uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcMap);
    if (hc) {
      cap = read32 (hc, 0x00);
      ver = read32 (hc, 0x08);
      is = read32 (hc, 0x20);
      hcs = read32 (hc, 0x30);
      hce = read32 (hc, 0x34);
      utrlba = read32 (hc, 0x50);
      readHc = 1;
    }
  }
  panic ("NATIVE_UFS inspect\n"
         "gdsc=%08x memphygdsc=%08x\n"
         "axi=%08x ahb=%08x unipro=%08x\n"
         "txsym=%08x rxsym=%08x aux=%08x\n"
         "hc_read=%u cap=%08x ver=%08x\n"
         "is=%08x hcs=%08x hce=%08x utrlba=%08x",
         gdsc, memGdsc, axi, ahb, unipro, txs, rxs, aux, readHc, cap, ver, is, hcs, hce, utrlba);
}

// Adopt the controller the firmware left running (native-ufs-probe=3) and issue
// read-only SCSI commands through one UTP transfer request slot. Nothing is written
// to the storage. The controller is not reset and the link is not restarted; the
// firmware's request list is stopped (refused if a request is outstanding) and replaced
// by ours. Interrupts stay masked and completion is polled.
namespace {
struct UfsResult {
  uint32_t ocs;      // UTRD overall command status; 0xf = never completed
  uint32_t response; // UPIU response byte
  uint32_t scsi;     // SCSI status byte
  uint32_t sense;    // sense key<<16 | ASC<<8 | ASCQ from the response UPIU's autosense data
  uint32_t senseLen; // sense data length reported by the device
  uint32_t seg;      // UPIU data segment length
};

static void be32 (uint8_t *at, uint32_t value)
{
  at[0] = value >> 24; at[1] = value >> 16; at[2] = value >> 8; at[3] = value;
}

static uint32_t getBe32 (const uint8_t *at)
{
  return (uint32_t (at[0]) << 24) | (uint32_t (at[1]) << 16) | (uint32_t (at[2]) << 8) | at[3];
}
}

static void cacheClean (const void *start, size_t length)
{
  uintptr_t address = reinterpret_cast<uintptr_t> (start) & ~uintptr_t (63);
  uintptr_t end = reinterpret_cast<uintptr_t> (start) + length;
  for (; address < end; address += 64) {
    __asm__ volatile ("dc cvac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

static void cacheCleanInvalidate (const void *start, size_t length)
{
  uintptr_t address = reinterpret_cast<uintptr_t> (start) & ~uintptr_t (63);
  uintptr_t end = reinterpret_cast<uintptr_t> (start) + length;
  for (; address < end; address += 64) {
    __asm__ volatile ("dc civac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

// The region is mapped as device memory: only aligned element-sized stores are allowed
// (bzero's block zeroing faulted on hardware, 2026-10-17).
static void zero32 (void *start, size_t length)
{
  volatile uint32_t *word = static_cast<volatile uint32_t *> (start);
  for (size_t index = 0; index < length / 4; index++) {
    word[index] = 0;
  }
}


// Give the UFS stream a pass-through mapping the way Linux does on this firmware.
// Hardware 2026-10-17: after hand-off apps_smmu has sCR0 = 0x002f0406 (USFCFG=1, unmatched
// streams fault), no stream-match entry for the UFS host (ID 0x60, `iommus = <&apps_smmu 0x60
// 0x0>` in the board DT), a TYPE=BYPASS S2CR reads back as FAULT, and sCR0 writes are ignored.
// Linux (drivers/iommu/arm/arm-smmu/arm-smmu-qcom.c, qcom_smmu_cfg_probe + qcom_smmu_write_s2cr,
// "bypass_quirk") meets exactly this: it reserves the LAST context bank (num_context_banks-1),
// writes SCTLR=0 (stage 1 disabled) and CBAR.TYPE=S1_TRANS_S2_BYPASS there, and maps a bypass
// stream as S2CR TYPE=TRANSLATE with CBNDX = that bank. S2CR is written before SMR
// (arm_smmu_write_sme). ARM IHI 0062D.c table 3-1 additionally requires VA64=1
// for inputs above 32 bits even with SCTLR.M=0. Storage DMA path only; this
// is physical pass-through, not a page-table or Adreno 4 KiB qualification.
static void smmuBypassStream (uint16_t stream, OSSharedPtr<IOMemoryMap> &keep, uint32_t *report,
                              uint64_t dma, uint64_t bytes)
{
  uintptr_t smmu = mapPhys (UFS_SMMU_BASE, UFS_SMMU_SIZE, keep);
  if (!smmu) {
    panic ("NATIVE_UFS smmu: map failed");
  }
  // erhai bring-up: native-ufs-smmu=0 leaves the SMMU exactly as the firmware handed it over
  // (no stream-match entry for the UFS stream) and reports sCR0 instead, to tell whether our
  // bypass mapping is what stops the controller's DMA.
  unsigned smmuMode = 1;
  PE_parse_boot_argn ("native-ufs-smmu", &smmuMode, sizeof (smmuMode));
  if (smmuMode == 0) {
    report[0] = 0xffffffffU;
    report[1] = read32 (smmu, 0x0);   // sCR0
    report[2] = read32 (smmu, 0x20);  // IDR0
    return;
  }
  UfsSmmuPlan plan = planUfsSmmu (stream, dma, bytes, [smmu](unsigned offset) { return read32 (smmu, offset); });
  gRootDiagnostic.smmuId1 = read32 (smmu, 0x24);
  gRootDiagnostic.smmuId2 = read32 (smmu, 0x28);
  gRootDiagnostic.smmuSlot = plan.slot;
  if (plan.error) {
    gRootDiagnostic.stage = "SMMU planning";
    gRootDiagnostic.result = static_cast<uint32_t> (kIOReturnNotReady);
    gRootDiagnostic.smr = plan.smr; gRootDiagnostic.s2cr = plan.s2cr;
    rootDiagnosticFailure (plan.error);
    panic ("NATIVE_UFS smmu: %s slot=%u smr=%x s2cr=%x idr0=%x idr1=%x idr2=%x", plan.error, plan.slot, plan.smr, plan.s2cr,
           read32 (smmu, 0x20), gRootDiagnostic.smmuId1, gRootDiagnostic.smmuId2);
  }
  unsigned bank = plan.bank, index = plan.slot;
  uintptr_t cb = smmu + (plan.pages + bank) * 4096;
  const char *failure = configureUfsSmmu (plan, stream,
    [smmu](unsigned offset) { return read32 (smmu, offset); },
    [smmu](unsigned offset, uint32_t value) {
      write32 (smmu, offset, value);
      __asm__ volatile ("dsb sy" ::: "memory");
    });
  uint32_t smr = read32 (smmu, 0x800 + 4 * index), s2cr = read32 (smmu, 0xc00 + 4 * index);
  uint32_t cbar = read32 (smmu, 0x1000 + 4 * bank), sctlr = read32 (cb, 0x0);
  gRootDiagnostic.smr = smr; gRootDiagnostic.s2cr = s2cr;
  gRootDiagnostic.cbar = cbar; gRootDiagnostic.sctlr = sctlr;
  gRootDiagnostic.smmuId2 = read32 (smmu, 0x28);
  gRootDiagnostic.cba2r = read32 (smmu, 0x1800 + 4 * bank);
  if (failure) {
    gRootDiagnostic.stage = "SMMU readback";
    gRootDiagnostic.result = static_cast<uint32_t> (kIOReturnNotReady);
    rootDiagnosticFailure (failure);
    panic ("NATIVE_UFS smmu: %s idx=%u bank=%u cba2r=%x", failure, index, bank,
           gRootDiagnostic.cba2r);
  }
  // erhai bring-up: native-ufs-smmu=2 turns that bank into an identity-mapped stage-1 context (one
  // level-1 table of 1 GiB blocks over the whole input range) instead of SCTLR.M=0 pass-through.
  // Hardware 2026-10-23: with the pass-through bank the first command's DMA stalls silently (no
  // context or global fault) on SM8750; Linux drives this SMMU with translating contexts only.
  if (smmuMode >= 2 && smmuMode <= 4) {
    unsigned ias = ufsSmmuAddressBits (read32 (smmu, 0x28) & 15);
    if (ias < 32 || ias > 39) {
      panic ("NATIVE_UFS smmu: identity map needs 32..39-bit input, idr2=%x", read32 (smmu, 0x28));
    }
    static IOBufferMemoryDescriptor *table;
    if (!table) {
      table = IOBufferMemoryDescriptor::inTaskWithOptions (
        kernel_task, static_cast<IOOptionBits> (kIODirectionInOut) | static_cast<IOOptionBits> (kIOMemoryPhysicallyContiguous) |
        static_cast<IOOptionBits> (kIOMemoryMapperNone), 8192, 4096);
    }
    uint64_t *entry = table ? static_cast<uint64_t *> (table->getBytesNoCopy ()) : nullptr;
    IOByteCount contiguous = 0;
    uint64_t tablePhys = table ? table->getPhysicalSegment (0, &contiguous, kIOMemoryMapperNone) : 0;
    if (!entry || !tablePhys || (tablePhys & 4095)) {
      panic ("NATIVE_UFS smmu: identity table allocation");
    }
    // Hardware 2026-10-23: a single level-1 page with T0SZ for the 36-bit IDR2.IAS faulted
    // (FSR TF, FSYNR0.PLVL=0): the walk really starts at level 0. Page 0 therefore works as
    // either: entry 0 is a table pointing at page 1 (level 0 reading: 0..512 GiB), entries
    // 1.. are 1 GiB blocks (level 1 reading; DMA never sits in the first GiB). Page 1 holds
    // the 512 level-1 blocks. Block: AttrIndx 0 (write-back), AP=01, inner shareable, AF.
    // native-ufs-smmu=4: blocks use AttrIndx 1 (normal non-cacheable, MAIR0 byte 1 = 0x44) so the
    // controller's DMA avoids the IO-coherent (snooping) path. Hardware 2026-10-23: with
    // write-back blocks the walk works (smmu=3 control faults as expected) yet the data access
    // after a successful translation stalls silently.
    uint64_t block = smmuMode == 4 ? 0x745 : 0x741;
    for (unsigned index = 0; index < 512; index++) {
      entry[index] = index ? ((uint64_t (index) << 30) | block) : ((tablePhys + 4096) | 3);
      entry[512 + index] = (uint64_t (index) << 30) | block;
    }
    if (smmuMode == 3) {
      // Control run: the walk itself still has to read both table pages, but the DMA's GiB is
      // left invalid, so a working walker must report a level-1 translation fault.
      entry[dma >> 30] = 0;
      entry[512 + (dma >> 30)] = 0;
    }
    cacheClean (entry, 8192);
    auto put = [cb] (unsigned offset, uint32_t value) {
      write32 (cb, offset, value);
      __asm__ volatile ("dsb sy" ::: "memory");
    };
    put (0x0, 0);                                         // SCTLR off while programming
    // TCR2: PASize = IDR2.OAS, SEP = upstream (7). Hardware 2026-10-23: with SEP=0 (sign bit 31)
    // the DMA address 0x8c806a000 was taken as a TTBR1 address and faulted at level 0 (EPD1).
    put (0x10, ((read32 (smmu, 0x28) >> 4) & 7) | (7U << 15));
    put (0x20, static_cast<uint32_t> (tablePhys));        // TTBR0, ASID 0
    put (0x24, static_cast<uint32_t> (tablePhys >> 32));
    put (0x28, 0);
    put (0x2c, 0);
    uint32_t tcr = (64 - ias) | (1U << 8) | (1U << 10) | (3U << 12) | (1U << 23);  // T0SZ, WB walks, IS, 4K, EPD1
    put (0x30, tcr);
    put (0x34, 0);
    put (0x38, 0x0444ff);                                 // MAIR0: attr0 WB, attr1 NC, attr2 device
    put (0x3c, 0);
    put (0x58, read32 (cb, 0x58));                        // clear stale FSR
    put (0x618, 0);                                       // TLBIALL
    put (0x7f0, 0);                                       // TLBSYNC
    for (unsigned loops = 0; (read32 (cb, 0x7f4) & 1) && loops < 100000; loops++) IODelay (1);
    put (0x0, 0x67);                                      // M | TRE | AFE | CFRE | CFIE, faults terminate
    sctlr = read32 (cb, 0x0);
    if (sctlr != 0x67 || read32 (cb, 0x30) != tcr) {
      panic ("NATIVE_UFS smmu: identity context readback sctlr=%x tcr=%x ttbr0=%x", sctlr, read32 (cb, 0x30), read32 (cb, 0x20));
    }
    gRootDiagnostic.sctlr = sctlr;
  }
  report[0] = index | (bank << 16);
  report[1] = cbar;
  report[2] = sctlr;
}

// One UIC command (UFSHCI 5.6: UICCMD 0x90, UCMDARG1..3 0x94..0x9c, IS.UCCS bit 10). Returns
// false on a timeout; the result code (UCMDARG2 bits 7:0) and value (UCMDARG3) go to the caller.
static bool uicCommand (uintptr_t hc, uint32_t opcode, uint32_t arg1, uint32_t *result, uint32_t *value)
{
  unsigned wait = 0;
  while (!(read32 (hc, 0x30) & 0x8) && wait++ < 100000) IODelay (1);
  if (!(read32 (hc, 0x30) & 0x8)) return false;
  write32 (hc, 0x20, 0x4b0);  // clear UCCS, UHXS, UHES, UPMS
  write32 (hc, 0x94, arg1);
  write32 (hc, 0x98, 0);
  write32 (hc, 0x9c, 0);
  __asm__ volatile ("dsb sy" ::: "memory");
  write32 (hc, 0x90, opcode);
  wait = 0;
  while (!(read32 (hc, 0x20) & 0x400) && wait++ < 200000) IODelay (1);
  if (!(read32 (hc, 0x20) & 0x400)) return false;
  if (result) *result = read32 (hc, 0x98) & 0xff;
  if (value) *value = read32 (hc, 0x9c);
  return true;
}

// erhai: the firmware hands over the UniPro link in Hibern8. Hardware 2026-10-23 (probes 16/17): local
// PA_PWRMODE 0x11 (FAST, HS-G5 x2) but DME_PEER_GET fails with PEER_COMMUNICATION_FAILURE and
// T_CONNECTIONSTATE is 0, so NOP OUT is fetched and never answered; DME_HIBERNATE_EXIT completes
// (IS.UHXS, HCS.UPMCRS = PWR_LOCAL) and the peer then answers with the CPort connected. When the
// peer already answers nothing is sent. Returns a reason on failure.
static const char *uicWakeLink (uintptr_t hc)
{
  uint32_t result = 0xff;
  if (uicCommand (hc, 0x03, 0x1571U << 16, &result, nullptr) && result == 0) return nullptr;
  if (!uicCommand (hc, 0x18, 0, nullptr, nullptr)) return "Hibern8 exit timeout";
  unsigned wait = 0;
  while (!(read32 (hc, 0x20) & 0x20) && wait++ < 200000) IODelay (1);
  if (!(read32 (hc, 0x20) & 0x20) || ((read32 (hc, 0x30) >> 8) & 7) != 1) return "Hibern8 exit status";
  result = 0xff;
  if (!uicCommand (hc, 0x03, 0x1571U << 16, &result, nullptr) || result != 0) return "peer silent after Hibern8 exit";
  return nullptr;
}

void NativeUfs::adoptAndRead (unsigned level)
{
  OSSharedPtr<IOMemoryMap> hcMap;
  uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcMap);
  if (!hc) {
    panic ("NATIVE_UFS adopt: controller map failed");
  }
  // The controller's own request list is the one region its DMA is known to reach
  // (hardware 2026-10-17: a kernel-allocated buffer at 0xf080f000 reset the system when the
  // first command was issued, and nothing below 0xc8000000 is allocatable). The firmware
  // zeroed it; use 16 KiB from UTRLBA as ordinary cached memory (the DT marks the host
  // dma-coherent). Test instrument only: the kernel may also own these pages.
  uint64_t fwList = (uint64_t (read32 (hc, 0x54)) << 32) | read32 (hc, 0x50);
  if (!fwList || (fwList & 0xfff)) {
    panic ("NATIVE_UFS adopt: no usable firmware list base=%llx", fwList);
  }
  IOMemoryDescriptor *region = IOMemoryDescriptor::withPhysicalAddress (fwList, 16384, kIODirectionInOut);
  OSSharedPtr<IOMemoryMap> regionMap;
  if (region) {
    regionMap = OSSharedPtr<IOMemoryMap> (region->map (kIOMapAnywhere), OSNoRetain);
    region->release ();
  }
  if (!regionMap) {
    panic ("NATIVE_UFS adopt: firmware list map failed base=%llx", fwList);
  }
  uint8_t *virt = reinterpret_cast<uint8_t *> (regionMap->getVirtualAddress ());
  uint64_t phys = fwList;
  zero32 (virt, 16384);
  cacheClean (virt, 16384);
  // Layout: [0,4096) request list (slot 0 used), [4096,5120) command + response UPIU +
  // PRDT, [8192,16384) data.
  const uint32_t ucdOffset = 4096, rspOffset = 512, prdtOffset = 1024, dataOffset = 8192;
  uint32_t hcsBefore = read32 (hc, 0x30);
  uint32_t doorbellBefore = read32 (hc, 0x58);
  if (doorbellBefore != 0 || read32 (hc, 0x78) != 0) {
    panic ("NATIVE_UFS adopt: firmware request outstanding doorbell=%08x hcs=%08x", doorbellBefore, hcsBefore);
  }
  OSSharedPtr<IOMemoryMap> smmuMap;
  uint32_t smmuReport[3] = { 0, 0, 0 };
  write32 (hc, 0x24, 0);            // mask interrupts
  write32 (hc, 0x60, 0);            // stop the firmware's request list
  __asm__ volatile ("dsb sy" ::: "memory");
  unsigned stopLoops = 10000;
  while ((read32 (hc, 0x60) & 1) && stopLoops--) IODelay (10);
  if (read32 (hc, 0x60) & 1) panic ("NATIVE_UFS adopt: request list did not stop");
  smmuBypassStream (0x60, smmuMap, smmuReport, phys, 16384);
  if (const char *wake = uicWakeLink (hc)) {
    panic ("NATIVE_UFS adopt: %s is=%08x hcs=%08x", wake, read32 (hc, 0x20), read32 (hc, 0x30));
  }
  write32 (hc, 0x50, static_cast<uint32_t> (phys));
  write32 (hc, 0x54, static_cast<uint32_t> (phys >> 32));
  write32 (hc, 0x20, 0xffffffffU);  // clear stale status
  write32 (hc, 0x60, 1);
  if (!waitSet (hc, 0x30, 0x2, 100000)) {
    panic ("NATIVE_UFS adopt: request list not ready hcs=%08x", read32 (hc, 0x30));
  }
  if (level == 3) {
    panic ("NATIVE_UFS adopt: list replaced\n"
           "phys=%llx hcs=%08x->%08x\n"
           "is=%08x db=%08x rsr=%08x ba=%08x bau=%08x ie=%08x",
           phys, hcsBefore, read32 (hc, 0x30), read32 (hc, 0x20), read32 (hc, 0x58),
           read32 (hc, 0x60), read32 (hc, 0x50), read32 (hc, 0x54), read32 (hc, 0x24));
  }

  auto command = [&] (uint8_t lun, const uint8_t *cdb, unsigned cdbLength, bool toHost, uint32_t length) -> UfsResult {
    uint8_t *utrd = virt;
    uint8_t *ucd = virt + ucdOffset;
    zero32 (utrd, 32);
    zero32 (ucd, 1024 + 16);
    zero32 (virt + dataOffset, 8192);
    ucd[0] = 0x01;                  // COMMAND UPIU
    ucd[1] = toHost ? 0x40 : 0x00;  // flags: read
    ucd[2] = lun;
    ucd[3] = 0;                     // task tag
    be32 (ucd + 12, length);        // expected data transfer length
    for (unsigned index = 0; index < cdbLength; index++) {
      ucd[16 + index] = cdb[index];
    }
    uint64_t ucdPhys = phys + ucdOffset;
    uint32_t direction = length ? (toHost ? 2U : 1U) : 0U;
    *reinterpret_cast<uint32_t *> (utrd + 0) = 0x10000000U | (direction << 25);
    *reinterpret_cast<uint32_t *> (utrd + 8) = 0x0fU;     // OCS: not completed
    *reinterpret_cast<uint32_t *> (utrd + 16) = static_cast<uint32_t> (ucdPhys);
    *reinterpret_cast<uint32_t *> (utrd + 20) = static_cast<uint32_t> (ucdPhys >> 32);
    *reinterpret_cast<uint32_t *> (utrd + 24) = (512U >> 2) | ((rspOffset >> 2) << 16);   // response length | offset (dwords)
    uint32_t prdEntries = length ? 1U : 0U;
    *reinterpret_cast<uint32_t *> (utrd + 28) = prdEntries | ((prdtOffset >> 2) << 16);
    if (length) {
      uint64_t dataPhys = phys + dataOffset;
      uint8_t *prd = ucd + prdtOffset;
      *reinterpret_cast<uint32_t *> (prd + 0) = static_cast<uint32_t> (dataPhys);
      *reinterpret_cast<uint32_t *> (prd + 4) = static_cast<uint32_t> (dataPhys >> 32);
      *reinterpret_cast<uint32_t *> (prd + 12) = length - 1;
    }
    cacheClean (virt, 16384);
    write32 (hc, 0x20, 0xffffffffU);
    write32 (hc, 0x58, 1);          // ring slot 0
    UfsResult result = { 0xf, 0xff, 0xff, 0, 0, 0 };
    bool done = false;
    for (unsigned loops = 0; loops < 100000; loops++) {
      if (!(read32 (hc, 0x58) & 1)) {
        done = true;
        break;
      }
      IODelay (1);
    }
    cacheCleanInvalidate (virt, 16384);
    if (!done) {
      return result;
    }
    result.ocs = *reinterpret_cast<volatile uint32_t *> (utrd + 8) & 0xff;
    const uint8_t *rsp = ucd + rspOffset;
    result.response = rsp[6];
    result.scsi = rsp[7];
    // Response UPIU: 12-byte header, residual count, 16 reserved bytes, then the data segment
    // (2-byte sense length + sense data) at offset 32.
    result.seg = (uint32_t (rsp[10]) << 8) | rsp[11];
    result.senseLen = (uint32_t (rsp[32]) << 8) | rsp[33];
    result.sense = ((rsp[36] & 0xfU) << 16) | (uint32_t (rsp[46]) << 8) | rsp[47];
    return result;
  };

  // NOP OUT (kind 0) and Query read requests (kind 1: opcode 0x05 READ FLAG, 0x03 READ ATTRIBUTE).
  // Read-only: no data segment, no state change on the device. Returns the UPIU response byte and
  // the 32-bit value field (attributes) or flag byte via *value; ocs 0xf means no completion.
  auto query = [&] (unsigned kind, uint8_t opcode, uint8_t idn, uint32_t *value, uint32_t *respByte) -> uint32_t {
    uint8_t *utrd = virt;
    uint8_t *ucd = virt + ucdOffset;
    zero32 (utrd, 32);
    zero32 (ucd, 1024 + 16);
    if (kind == 0) {
      ucd[0] = 0x00;                // NOP OUT
    } else {
      ucd[0] = 0x16;                // QUERY REQUEST
      ucd[5] = 0x01;                // query function (header dword 1, byte 1): standard read request
      ucd[12] = opcode;
      ucd[13] = idn;
    }
    ucd[3] = 1;                     // task tag
    uint64_t ucdPhys = phys + ucdOffset;
    *reinterpret_cast<uint32_t *> (utrd + 0) = 0x10000000U;
    *reinterpret_cast<uint32_t *> (utrd + 8) = 0x0fU;
    *reinterpret_cast<uint32_t *> (utrd + 16) = static_cast<uint32_t> (ucdPhys);
    *reinterpret_cast<uint32_t *> (utrd + 20) = static_cast<uint32_t> (ucdPhys >> 32);
    *reinterpret_cast<uint32_t *> (utrd + 24) = (512U >> 2) | ((rspOffset >> 2) << 16);
    *reinterpret_cast<uint32_t *> (utrd + 28) = (prdtOffset >> 2) << 16;
    cacheClean (virt, 16384);
    write32 (hc, 0x20, 0xffffffffU);
    write32 (hc, 0x58, 1);
    bool done = false;
    for (unsigned loops = 0; loops < 100000; loops++) {
      if (!(read32 (hc, 0x58) & 1)) {
        done = true;
        break;
      }
      IODelay (1);
    }
    cacheCleanInvalidate (virt, 16384);
    if (!done) {
      return 0xf;
    }
    const uint8_t *rsp = ucd + rspOffset;
    *respByte = (uint32_t (rsp[0]) << 8) | rsp[6];     // response type << 8 | query/NOP response
    *value = getBe32 (rsp + 20);
    return *reinterpret_cast<volatile uint32_t *> (utrd + 8) & 0xff;
  };
  // Device state before waking it. Hardware 2026-10-17: NOP OUT answers, fDeviceInit = 0 (done),
  // bCurrentPowerMode = 0x33 (UFS-PowerDown) and every LU returns NOT READY. Linux resumes the
  // device with START STOP UNIT (power condition ACTIVE) to the UFS Device well-known LU 0xD0
  // (ufshcd_set_dev_pwr_mode); no user data is touched.
  uint32_t powerBefore = 0, powerAfter = 0, queryResp = 0, ignoredValue = 0;
  uint32_t wakeStatus = 0xee;
  if (level == 5 || level == 9) {
    query (1, 0x03, 0x02, &powerBefore, &queryResp);     // READ ATTRIBUTE bCurrentPowerMode
    uint8_t ssu[6] = { 0x1b, 0, 0, 0, 0x10, 0 };          // START STOP UNIT, power condition ACTIVE
    UfsResult w = command (0xd0, ssu, 6, false, 0);
    wakeStatus = (w.ocs << 16) | (w.response << 8) | w.scsi;
    for (unsigned settle = 0; settle < 50; settle++) {
      IODelay (1000);
    }
    query (1, 0x03, 0x02, &powerAfter, &queryResp);
    (void) ignoredValue;
  }
  if (level == 4) {
    uint8_t tur0[6] = { 0, 0, 0, 0, 0, 0 };
    UfsResult t = command (0, tur0, 6, false, 0);
    const uint8_t *rsp0 = virt + ucdOffset + rspOffset;
    panic ("NATIVE_UFS adopt: TEST UNIT READY lun0\n"
           "ocs=%x resp=%02x scsi=%02x\n"
           "phys=%llx hcs=%08x->%08x smmu idx/bank=%08x cbar=%08x\n"
           "is=%08x db=%08x rsr=%08x\n"
           "rsp=%08x %08x",
           t.ocs, t.response, t.scsi, phys, hcsBefore, read32 (hc, 0x30), smmuReport[0], smmuReport[1],
           read32 (hc, 0x20), read32 (hc, 0x58), read32 (hc, 0x60), getBe32 (rsp0), getBe32 (rsp0 + 4));
  }
  uint32_t hcsAfter = 0;
  const unsigned maxLun = 6;
  uint32_t status[maxLun], last[maxLun], blockSize[maxLun], senseOf[maxLun];
  for (unsigned lun = 0; lun < maxLun; lun++) {
    status[lun] = 0xee; last[lun] = 0; blockSize[lun] = 0; senseOf[lun] = 0;
    uint8_t tur[6] = { 0x00, 0, 0, 0, 0, 0 };
    UfsResult r = { 0xf, 0xff, 0xff, 0, 0, 0 };
    for (unsigned attempt = 0; attempt < 3; attempt++) {
      r = command (static_cast<uint8_t> (lun), tur, 6, false, 0);
      if (lun == 0 && attempt == 0 && r.ocs == 0xf) {
        // Never completed: stop here and report instead of waiting out every command.
        const uint8_t *rsp = virt + ucdOffset + rspOffset;
        panic ("NATIVE_UFS adopt: first command did not complete\n"
               "phys=%llx hcs=%08x->%08x\n"
               "is=%08x db=%08x rsr=%08x ba=%08x\n"
               "utrd2=%08x rsp=%08x %08x",
               phys, hcsBefore, read32 (hc, 0x30),
               read32 (hc, 0x20), read32 (hc, 0x58), read32 (hc, 0x60), read32 (hc, 0x50),
               *reinterpret_cast<volatile uint32_t *> (virt + 8), getBe32 (rsp), getBe32 (rsp + 4));
      }
      if (r.ocs == 0 && r.scsi == 0) {
        break;
      }
    }
    uint8_t cap[10] = { 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    r = command (static_cast<uint8_t> (lun), cap, 10, true, 8);
    status[lun] = (r.ocs << 16) | (r.response << 8) | r.scsi;
    senseOf[lun] = r.sense;
    if (r.ocs == 0 && r.scsi == 0) {
      last[lun] = getBe32 (virt + dataOffset);
      blockSize[lun] = getBe32 (virt + dataOffset + 4);
    }
  }
  if (level == 9) {
    // Read-only GPT survey of LUN 0 (4096-byte blocks): header fields and CRCs for before/after
    // comparison, then every non-empty entry among the first 64. Nothing is written.
    if (blockSize[0] != 4096) {
      panic ("NATIVE_UFS gpt: unexpected LUN0 block size %08x", blockSize[0]);
    }
    uint8_t rd[10] = { 0x28, 0, 0, 0, 0, 1, 0, 0, 1, 0 };
    UfsResult h = command (0, rd, 10, true, 4096);
    if (h.ocs != 0 || h.scsi != 0) {
      panic ("NATIVE_UFS gpt: header read failed ocs=%x resp=%x scsi=%x", h.ocs, h.response, h.scsi);
    }
    const uint8_t *hdr = virt + dataOffset;
    auto le32 = [] (const uint8_t *at) -> uint32_t {
      return uint32_t (at[0]) | (uint32_t (at[1]) << 8) | (uint32_t (at[2]) << 16) | (uint32_t (at[3]) << 24);
    };
    auto le64 = [&] (const uint8_t *at) -> uint64_t {
      return uint64_t (le32 (at)) | (uint64_t (le32 (at + 4)) << 32);
    };
    uint32_t sig0 = le32 (hdr), sig1 = le32 (hdr + 4), hdrCrc = le32 (hdr + 16), entCrc = le32 (hdr + 88);
    uint64_t curLba = le64 (hdr + 24), bakLba = le64 (hdr + 32), firstUsable = le64 (hdr + 40), lastUsable = le64 (hdr + 48);
    uint64_t entLba = le64 (hdr + 72);
    uint32_t entCount = le32 (hdr + 80), entSize = le32 (hdr + 84);
    uint32_t guid0 = le32 (hdr + 56), guid1 = le32 (hdr + 60), guid2 = le32 (hdr + 64), guid3 = le32 (hdr + 68);
    if (sig0 != 0x20494645U || sig1 != 0x54524150U || entSize != 128 || entLba > 64) {
      panic ("NATIVE_UFS gpt: unexpected header sig=%08x %08x esz=%u elba=%llx", sig0, sig1, entSize, entLba);
    }
    uint32_t shown = entCount > 64 ? 64 : entCount;
    uint32_t blocks = (shown * 128 + 4095) / 4096;
    uint8_t rd2[10] = { 0x28, 0, 0, 0, 0, uint8_t (entLba), 0, 0, uint8_t (blocks), 0 };
    UfsResult e = command (0, rd2, 10, true, blocks * 4096);
    if (e.ocs != 0 || e.scsi != 0) {
      panic ("NATIVE_UFS gpt: entries read failed ocs=%x scsi=%x", e.ocs, e.scsi);
    }
    const uint8_t *ents = virt + dataOffset;
    static char text[3400];
    int used = snprintf (text, sizeof (text),
                         "NATIVE_UFS gpt LUN0 hdr crc=%08x ents crc=%08x cnt=%u\n"
                         "cur=%llx backup=%llx usable=%llx..%llx elba=%llx\n"
                         "disk guid %08x %08x %08x %08x last=%08x\n",
                         hdrCrc, entCrc, entCount, curLba, bakLba, firstUsable, lastUsable, entLba,
                         guid0, guid1, guid2, guid3, last[0]);
    unsigned column = 0, listed = 0;
    for (uint32_t index = 0; index < shown && used < int (sizeof (text)) - 80; index++) {
      const uint8_t *entry = ents + index * 128;
      bool empty = true;
      for (unsigned b = 0; b < 16; b++) {
        if (entry[b]) { empty = false; break; }
      }
      if (empty) {
        continue;
      }
      char name[14];
      for (unsigned c = 0; c < 13; c++) {
        uint8_t lo = entry[56 + 2 * c], hi = entry[57 + 2 * c];
        name[c] = (hi == 0 && lo >= 32 && lo < 127) ? char (lo) : (lo ? '?' : 0);
        if (!name[c]) { name[c] = 0; break; }
      }
      name[13] = 0;
      used += snprintf (text + used, sizeof (text) - used, "%u:%s %llx-%llx%s", index, name,
                        le64 (entry + 32), le64 (entry + 40), (++column % 3) ? "  " : "\n");
      listed++;
    }
    snprintf (text + used, sizeof (text) - used, "\nlisted=%u", listed);
    panic ("%s", text);
  }
  // INQUIRY of LUN 0: vendor/product bytes 8..23.
  uint8_t inquiry[6] = { 0x12, 0, 0, 0, 36, 0 };
  UfsResult inq = command (0, inquiry, 6, true, 36);
  uint32_t inqWord[4] = { 0, 0, 0, 0 };
  for (unsigned index = 0; index < 4; index++) {
    inqWord[index] = getBe32 (virt + dataOffset + 8 + index * 4);
  }
  // LBA 1 of LUN 0 holds the GPT header when the block size is 4096 (or 512).
  uint32_t gptStatus = 0xee, sig0 = 0, sig1 = 0;
  if (blockSize[0] >= 512 && blockSize[0] <= 4096) {
    uint8_t read10[10] = { 0x28, 0, 0, 0, 0, 1, 0, 0, 1, 0 };
    UfsResult g = command (0, read10, 10, true, blockSize[0]);
    gptStatus = (g.ocs << 16) | (g.response << 8) | g.scsi;
    if (g.ocs == 0 && g.scsi == 0) {
      sig0 = *reinterpret_cast<uint32_t *> (virt + dataOffset);
      sig1 = *reinterpret_cast<uint32_t *> (virt + dataOffset + 4);
    }
  }
  hcsAfter = read32 (hc, 0x30);
  panic ("NATIVE_UFS adopt+read\n"
         "hcs %08x->%08x pwr %08x->%08x ssu=%06x\n"
         "L0 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L1 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L2 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L3 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L4 st=%06x last=%08x bs=%08x sns=%06x\n"
         "L5 st=%06x last=%08x bs=%08x sns=%06x\n"
         "inq st=%06x %08x %08x %08x %08x\n"
         "inq sns=%06x slen=%x seg=%x\n"
         "rsp0 %08x %08x %08x %08x\n"
         "rsp8 %08x %08x %08x %08x\n"
         "gpt st=%06x sig=%08x %08x",
         hcsBefore, hcsAfter, powerBefore, powerAfter, wakeStatus,
         status[0], last[0], blockSize[0], senseOf[0], status[1], last[1], blockSize[1], senseOf[1],
         status[2], last[2], blockSize[2], senseOf[2], status[3], last[3], blockSize[3], senseOf[3],
         status[4], last[4], blockSize[4], senseOf[4], status[5], last[5], blockSize[5], senseOf[5],
         (inq.ocs << 16) | (inq.response << 8) | inq.scsi, inqWord[0], inqWord[1], inqWord[2], inqWord[3],
         inq.sense, inq.senseLen, inq.seg,
         getBe32 (virt + ucdOffset + rspOffset), getBe32 (virt + ucdOffset + rspOffset + 4),
         getBe32 (virt + ucdOffset + rspOffset + 8), getBe32 (virt + ucdOffset + rspOffset + 12),
         getBe32 (virt + ucdOffset + rspOffset + 32), getBe32 (virt + ucdOffset + rspOffset + 36),
         getBe32 (virt + ucdOffset + rspOffset + 40), getBe32 (virt + ucdOffset + rspOffset + 44),
         gptStatus, sig0, sig1);
}

// Read-only dump of the request list the firmware left (native-ufs-probe=6): shows where
// the firmware placed its descriptors, to compare with an allocation the controller's DMA
// is known to reach. Nothing is written and no register is touched except reads.
static uint32_t dumpWord (const volatile uint32_t *base, unsigned index)
{
  return base[index];
}

void NativeUfs::dumpFirmwareList (void)
{
  OSSharedPtr<IOMemoryMap> hcMap, listMap, ucdMap;
  uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcMap);
  if (!hc) {
    panic ("NATIVE_UFS dump: controller map failed");
  }
  uint64_t listPhys = (uint64_t (read32 (hc, 0x54)) << 32) | read32 (hc, 0x50);
  uint32_t db = read32 (hc, 0x58), rsr = read32 (hc, 0x60), hcs = read32 (hc, 0x30);
  IOMemoryDescriptor *listDesc = IOMemoryDescriptor::withPhysicalAddress (listPhys, 4096, kIODirectionIn);
  if (!listDesc) {
    panic ("NATIVE_UFS dump: list descriptor failed phys=%llx", listPhys);
  }
  listMap = OSSharedPtr<IOMemoryMap> (listDesc->map (kIOMapAnywhere), OSNoRetain);
  listDesc->release ();
  if (!listMap) {
    panic ("NATIVE_UFS dump: list map failed phys=%llx", listPhys);
  }
  const volatile uint32_t *utrd = reinterpret_cast<const volatile uint32_t *> (listMap->getVirtualAddress ());
  uint64_t ucdPhys = (uint64_t (dumpWord (utrd, 5)) << 32) | dumpWord (utrd, 4);
  uint32_t ucd0 = 0, ucd1 = 0, ucd2 = 0, ucd3 = 0;
  if (ucdPhys) {
    IOMemoryDescriptor *ucdDesc = IOMemoryDescriptor::withPhysicalAddress (ucdPhys, 4096, kIODirectionIn);
    if (ucdDesc) {
      ucdMap = OSSharedPtr<IOMemoryMap> (ucdDesc->map (kIOMapAnywhere), OSNoRetain);
      ucdDesc->release ();
      if (ucdMap) {
        const volatile uint32_t *ucd = reinterpret_cast<const volatile uint32_t *> (ucdMap->getVirtualAddress ());
        ucd0 = dumpWord (ucd, 0); ucd1 = dumpWord (ucd, 1); ucd2 = dumpWord (ucd, 2); ucd3 = dumpWord (ucd, 3);
      }
    }
  }
  panic ("NATIVE_UFS dump: firmware list\n"
         "list=%llx hcs=%08x db=%08x rsr=%08x\n"
         "utrd0 %08x %08x %08x %08x\n"
         "utrd0 %08x %08x %08x %08x\n"
         "utrd1 %08x %08x %08x %08x\n"
         "ucd=%llx %08x %08x %08x %08x",
         listPhys, hcs, db, rsr,
         dumpWord (utrd, 0), dumpWord (utrd, 1), dumpWord (utrd, 2), dumpWord (utrd, 3),
         dumpWord (utrd, 4), dumpWord (utrd, 5), dumpWord (utrd, 6), dumpWord (utrd, 7),
         dumpWord (utrd, 8), dumpWord (utrd, 9), dumpWord (utrd, 10), dumpWord (utrd, 11),
         ucdPhys, ucd0, ucd1, ucd2, ucd3);
}

// Read-only dump of the apps SMMU (apps_smmu@15000000) global register space and the stream
// match entry for the UFS stream ID 0x60 (native-ufs-probe=7). SMMUv2 layout: sCR0 0x0,
// IDR0 0x20, sGFSR 0x48, SMR(n) 0x800+4n, S2CR(n) 0xc00+4n. Nothing is written.
void NativeUfs::inspectSmmu (void)
{
  OSSharedPtr<IOMemoryMap> map;
  uintptr_t smmu = mapPhys (UFS_SMMU_BASE, 0x1000, map);
  if (!smmu) {
    panic ("NATIVE_UFS smmu: map failed");
  }
  uint32_t scr0 = read32 (smmu, 0x00), idr0 = read32 (smmu, 0x20), idr1 = read32 (smmu, 0x24);
  uint32_t gfsr = read32 (smmu, 0x48);
  unsigned count = idr0 & 0xff;
  if (count > 128) {
    count = 128;
  }
  unsigned match = 0xffff, valid = 0, typeCount[4] = { 0, 0, 0, 0 };
  uint32_t matchSmr = 0, matchS2cr = 0;
  for (unsigned index = 0; index < count; index++) {
    uint32_t smr = read32 (smmu, 0x800 + 4 * index);
    uint32_t s2cr = read32 (smmu, 0xc00 + 4 * index);
    if (smr & 0x80000000U) {
      valid++;
      typeCount[(s2cr >> 16) & 3]++;
      uint32_t mask = (smr >> 16) & 0x7fff;
      if (match == 0xffff && (((smr ^ 0x60U) & 0x7fffU) & ~mask) == 0) {
        match = index;
        matchSmr = smr;
        matchS2cr = s2cr;
      }
    }
  }
  panic ("NATIVE_UFS smmu\n"
         "scr0=%08x idr0=%08x idr1=%08x gfsr=%08x\n"
         "nsmr=%u valid=%u types t0=%u t1=%u t2=%u\n"
         "sid0x60 match=%x smr=%08x s2cr=%08x",
         scr0, idr0, idr1, gfsr, count, valid, typeCount[0], typeCount[1], typeCount[2],
         match, matchSmr, matchS2cr);
}

// Read-only context-bank survey (native-ufs-probe=8): CBAR/CBA2R in gr1 and SCTLR/TTBR0 in the
// context banks, to find a bank the hypervisor leaves to us. Nothing is written.
// erhai probe 15 (read-only): the whole stream-routing picture in one panic. Global registers,
// every valid stream-match entry (index:SMR/S2CR; S2CR type 0 = context bank, 1 = bypass,
// 2 = fault), and the top context banks a UFS mapping would take. Nothing is written.
void NativeUfs::dumpSmmuStreams (void)
{
  OSSharedPtr<IOMemoryMap> map;
  uintptr_t smmu = mapPhys (UFS_SMMU_BASE, UFS_SMMU_SIZE, map);
  if (!smmu) {
    panic ("NATIVE_UFS streams: map failed");
  }
  uint32_t idr0 = read32 (smmu, 0x20), idr1 = read32 (smmu, 0x24);
  unsigned count = idr0 & 0xff, numCb = idr1 & 0xff;
  unsigned pages = 1U << (((idr1 >> 28) & 7) + 1);
  if (count > 128) count = 128;
  if (numCb > 128 || (pages + numCb) * 0x1000 > UFS_SMMU_SIZE) {
    panic ("NATIVE_UFS streams: unexpected geometry idr1=%08x", idr1);
  }
  static char text[2400];
  int used = snprintf (text, sizeof (text),
                       "NATIVE_UFS streams\nscr0=%08x scr2=%08x idr0=%08x idr1=%08x idr2=%08x\ngfsr=%08x gfsynr0=%08x nsmr=%u ncb=%u pages=%u\n",
                       read32 (smmu, 0x0), read32 (smmu, 0x8), idr0, idr1, read32 (smmu, 0x28),
                       read32 (smmu, 0x48), read32 (smmu, 0x50), count, numCb, pages);
  unsigned shown = 0, valid = 0, types[4] = {0, 0, 0, 0};
  for (unsigned index = 0; index < count; index++) {
    uint32_t smr = read32 (smmu, 0x800 + 4 * index);
    if (!(smr & 0x80000000U)) continue;
    uint32_t s2cr = read32 (smmu, 0xc00 + 4 * index);
    valid++;
    types[(s2cr >> 16) & 3]++;
    if (shown < 30 && used < int (sizeof (text)) - 400) {
      used += snprintf (text + used, sizeof (text) - used, "%u:%x/%x%s", index, smr & 0x7fffffffU, s2cr,
                        (++shown % 4) ? "  " : "\n");
    }
  }
  used += snprintf (text + used, sizeof (text) - used, "\nvalid=%u t0=%u t1=%u t2=%u\n", valid, types[0], types[1], types[2]);
  for (unsigned back = 1; back <= 4 && back <= numCb; back++) {
    unsigned bank = numCb - back;
    uintptr_t cb = smmu + (pages + bank) * 0x1000;
    used += snprintf (text + used, sizeof (text) - used, "cb%u cbar=%08x cba2r=%08x sctlr=%08x actlr=%08x fsr=%08x\n",
                      bank, read32 (smmu, 0x1000 + 4 * bank), read32 (smmu, 0x1800 + 4 * bank),
                      read32 (cb, 0x0), read32 (cb, 0x4), read32 (cb, 0x58));
  }
  panic ("%s", text);
}

// erhai probe 16 (read-only): the UniPro link as the firmware left it, through UIC DME_GET /
// DME_PEER_GET (UFSHCI 5.6: UICCMD 0x90, UCMDARG1..3 0x94..0x9c, IS.UCCS bit 10). Hardware
// 2026-10-23: with a working stage-1 mapping NOP OUT is fetched (a deliberately broken table
// faults on the request list) yet never completes, so check whether the link is up at all.
void NativeUfs::dumpUicState (bool hibernateExit)
{
  OSSharedPtr<IOMemoryMap> map;
  uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, map);
  if (!hc) {
    panic ("NATIVE_UFS uic: map failed");
  }
  uint32_t hcs = read32 (hc, 0x30), is = read32 (hc, 0x20);
  static char text[1600];
  int used = snprintf (text, sizeof (text), "NATIVE_UFS uic\nhcs=%08x is=%08x hce=%08x ahit=%08x uecpa=%08x uecdl=%08x\n",
                       hcs, is, read32 (hc, 0x34), read32 (hc, 0x18), read32 (hc, 0x38), read32 (hc, 0x3c));
  // Probe 17: hardware 2026-10-23 (probe 16) showed a FAST HS-G5 x2 link whose peer does not answer
  // (DME_PEER_GET = PEER_COMMUNICATION_FAILURE) and T_CONNECTIONSTATE 0, as if the firmware left the
  // link in Hibern8. Send DME_HIBERNATE_EXIT (0x18) and report its completion (IS.UHXS bit 5,
  // IS.UPMS bit 4, HCS.UPMCRS) before the same reads.
  if (hibernateExit) {
    unsigned wait = 0;
    while (!(read32 (hc, 0x30) & 0x8) && wait++ < 100000) IODelay (1);
    write32 (hc, 0x20, 0x4b0);                         // clear UCCS, UHXS, UHES, UPMS
    write32 (hc, 0x94, 0);
    write32 (hc, 0x98, 0);
    write32 (hc, 0x9c, 0);
    __asm__ volatile ("dsb sy" ::: "memory");
    write32 (hc, 0x90, 0x18);
    wait = 0;
    while (!(read32 (hc, 0x20) & 0x20) && wait++ < 200000) IODelay (1);
    used += snprintf (text + used, sizeof (text) - used, "h8exit is=%08x hcs=%08x arg2=%x waited=%u\n",
                      read32 (hc, 0x20), read32 (hc, 0x30), read32 (hc, 0x98), wait);
  }
  struct Attribute { uint16_t id; bool peer; const char *name; };
  static const Attribute attributes[] = {
    {0x1571, false, "pwrmode"}, {0x1568, false, "txgear"}, {0x1583, false, "rxgear"},
    {0x1561, false, "contx"}, {0x1581, false, "conrx"}, {0x1560, false, "acttx"}, {0x1580, false, "actrx"},
    {0x156a, false, "hsseries"}, {0x4020, false, "tconn"}, {0xd083, false, "vspwr"}, {0x15a7, false, "hib8time"},
    {0x1571, true, "peer-pwrmode"}, {0x4020, true, "peer-tconn"},
  };
  unsigned column = 0;
  for (const Attribute &attribute : attributes) {
    unsigned wait = 0;
    while (!(read32 (hc, 0x30) & 0x8) && wait++ < 100000) IODelay (1);
    if (!(read32 (hc, 0x30) & 0x8)) {
      used += snprintf (text + used, sizeof (text) - used, "\n%s: UCRDY never set", attribute.name);
      break;
    }
    write32 (hc, 0x20, 0x400);                         // clear UCCS
    write32 (hc, 0x94, uint32_t (attribute.id) << 16);  // MIB attribute, selector 0
    write32 (hc, 0x98, 0);
    write32 (hc, 0x9c, 0);
    __asm__ volatile ("dsb sy" ::: "memory");
    write32 (hc, 0x90, attribute.peer ? 0x03 : 0x01);   // DME_PEER_GET / DME_GET
    wait = 0;
    while (!(read32 (hc, 0x20) & 0x400) && wait++ < 100000) IODelay (1);
    bool done = read32 (hc, 0x20) & 0x400;
    used += snprintf (text + used, sizeof (text) - used, "%s=%s%x/%x%s", attribute.name, done ? "" : "TIMEOUT ",
                      read32 (hc, 0x98) & 0xff, read32 (hc, 0x9c), (++column % 4) ? "  " : "\n");
    if (!done) break;
  }
  used += snprintf (text + used, sizeof (text) - used, "\nafter is=%08x hcs=%08x", read32 (hc, 0x20), read32 (hc, 0x30));
  panic ("%s", text);
}

void NativeUfs::inspectContextBanks (void)
{
  OSSharedPtr<IOMemoryMap> map;
  uintptr_t smmu = mapPhys (UFS_SMMU_BASE, UFS_SMMU_SIZE, map);
  if (!smmu) {
    panic ("NATIVE_UFS cb: map failed");
  }
  uint32_t idr1 = read32 (smmu, 0x24);
  unsigned numCb = idr1 & 0xff;
  unsigned globalPages = 1U << (((idr1 >> 28) & 7) + 1);
  if (globalPages > 128 || numCb > 128 || (globalPages + numCb) * 0x1000 > UFS_SMMU_SIZE) {
    panic ("NATIVE_UFS cb: unexpected geometry idr1=%08x", idr1);
  }
  unsigned cbarZero = 0, sctlrZero = 0, mSet = 0, bothZero = 0;
  uint32_t firstZero = 0xffff;
  for (unsigned index = 0; index < numCb; index++) {
    uint32_t cbar = read32 (smmu, 0x1000 + 4 * index);
    uint32_t sctlr = read32 (smmu + (globalPages + index) * 0x1000, 0x0);
    cbarZero += cbar == 0;
    sctlrZero += sctlr == 0;
    mSet += (sctlr & 1) != 0;
    if (cbar == 0 && sctlr == 0) {
      bothZero++;
      if (firstZero == 0xffff) {
        firstZero = index;
      }
    }
  }
  uintptr_t cb0 = smmu + globalPages * 0x1000, cb1 = cb0 + 0x1000, cbLast = cb0 + (numCb - 1) * 0x1000;
  panic ("NATIVE_UFS cb survey\n"
         "ncb=%u pages=%u cbar0=%u sctlr0=%u msset=%u both0=%u first0=%x\n"
         "cbar[0]=%08x cbar[1]=%08x cbar[%u]=%08x\n"
         "sctlr[0]=%08x sctlr[1]=%08x sctlr[last]=%08x\n"
         "cba2r[0]=%08x cba2r[1]=%08x",
         numCb, globalPages, cbarZero, sctlrZero, mSet, bothZero, firstZero,
         read32 (smmu, 0x1000), read32 (smmu, 0x1004), numCb - 1, read32 (smmu, 0x1000 + 4 * (numCb - 1)),
         read32 (cb0, 0), read32 (cb1, 0), read32 (cbLast, 0),
         read32 (smmu, 0x1800), read32 (smmu, 0x1804));
}

// ======================================================================================
// Root media: the live controller as a read-only block device.
//
// One shared host (a single UTP request slot, polled; interrupts stay masked) serves every
// block device. The DMA region is ordinary cached, physically contiguous kernel memory with
// explicit cache maintenance around each command (the stream is mapped through the reserved
// apps_smmu bypass context bank by smmuBypassStream, so physical addresses are used as-is).
// Nothing here writes to the storage: only INQUIRY-class and READ(10) commands are built, plus
// the single START STOP UNIT that wakes the device from the power-down the firmware left.
// ======================================================================================
namespace {
#include "RootTransportLayout.h"

struct UfsHost {
  OSSharedPtr<IOMemoryMap> hcMap, smmuMap;
  uintptr_t hc;
  IOBufferMemoryDescriptor *dma;
  uint8_t *virt;
  uint64_t phys;
  IOLock *lock;
  bool ready;
  bool poisoned = false;
  uintptr_t smmu = 0, cb = 0;
};
UfsHost gHost = { OSSharedPtr<IOMemoryMap> (), OSSharedPtr<IOMemoryMap> (), 0, nullptr, nullptr, 0, nullptr, false };

static IOReturn recordTransport (IOReturn result, uint32_t ocs)
{
  gRootDiagnostic.result = static_cast<uint32_t> (result);
  gRootDiagnostic.ocs = ocs;
  if (result != kIOReturnSuccess && gRootDiagnosticEnabled) {
    // Read only the already mapped HC's status/registers used by this driver.
    gRootDiagnostic.hcs = read32 (gHost.hc, 0x30);
    gRootDiagnostic.hce = read32 (gHost.hc, 0x34);
    gRootDiagnostic.doorbell = read32 (gHost.hc, 0x58);
    gRootDiagnostic.interrupt = read32 (gHost.hc, 0x20);
    gRootDiagnostic.list = uint64_t (read32 (gHost.hc, 0x50)) |
                          (uint64_t (read32 (gHost.hc, 0x54)) << 32);
    gRootDiagnostic.runStop = read32 (gHost.hc, 0x60);
    gRootDiagnostic.ahit = read32 (gHost.hc, 0x18);
    for (unsigned i = 0; i < 5; ++i) gRootDiagnostic.uic[i] = read32 (gHost.hc, 0x38 + 4 * i);
    if (gHost.smmu && gHost.cb) {
      gRootDiagnostic.gfsr = read32 (gHost.smmu, 0x48);
      gRootDiagnostic.gsyn = read32 (gHost.smmu, 0x54);
      gRootDiagnostic.fsr = read32 (gHost.cb, 0x58);
      gRootDiagnostic.fsyn = read32 (gHost.cb, 0x68);
      gRootDiagnostic.far = uint64_t (read32 (gHost.cb, 0x60)) |
                            (uint64_t (read32 (gHost.cb, 0x64)) << 32);
    }
  }
  return result;
}

static void cacheCivac (const void *start, size_t length)
{
  uintptr_t address = reinterpret_cast<uintptr_t> (start) & ~uintptr_t (63);
  uintptr_t end = reinterpret_cast<uintptr_t> (start) + length;
  for (; address < end; address += 64) {
    __asm__ volatile ("dc civac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

// Device-owned cache lines must not be written back over DMA results. All
// callers use complete 64-byte lines from the dedicated page-aligned buffer.
static void cacheInvalidate (const void *start, size_t length)
{
  __asm__ volatile ("dsb sy" ::: "memory");
  uintptr_t address = reinterpret_cast<uintptr_t> (start);
  for (uintptr_t end = address + length; address < end; address += 64) {
    __asm__ volatile ("dc ivac, %0" :: "r" (address) : "memory");
  }
  __asm__ volatile ("dsb sy" ::: "memory");
}

static void hostWrite (unsigned offset, uint32_t value)
{
  __asm__ volatile ("dsb sy" ::: "memory");
  write32 (gHost.hc, offset, value);
  __asm__ volatile ("dsb sy" ::: "memory");
}

#include "RootQueue.h"

#include "RootCommands.h"

// Bring the live controller up for reading: map, SMMU pass-through for the UFS stream, take over
// the request list, wake the device from UFS-PowerDown and wait for LUN 0 to be ready.
// `why` receives a short reason on failure.
static bool hostBringUp (const char **why)
{
  if (gHost.poisoned) {
    *why = "transport quarantined";
    return false;
  }
  if (gHost.ready) {
    return true;
  }
  gRootDiagnostic.stage = "controller map";
  gHost.hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, gHost.hcMap);
  if (!gHost.hc) {
    *why = "controller map";
    return false;
  }
  if (gRootDiagnosticEnabled) {
    gRootDiagnostic.cap = read32 (gHost.hc, 0x00);
    gRootDiagnostic.version = read32 (gHost.hc, 0x08);
    gRootDiagnostic.hcs = read32 (gHost.hc, 0x30);
    gRootDiagnostic.hce = read32 (gHost.hc, 0x34);
  }
  gRootDiagnostic.stage = "DMA allocation";
  gHost.dma = IOBufferMemoryDescriptor::inTaskWithOptions (
    kernel_task, static_cast<IOOptionBits> (kIODirectionInOut) | static_cast<IOOptionBits> (kIOMemoryPhysicallyContiguous) |
    static_cast<IOOptionBits> (kIOMemoryMapperNone),
    kDmaBytes, 4096);
  gHost.lock = IOLockAlloc ();
  if (!gHost.dma || !gHost.lock) {
    *why = "dma buffer";
    return false;
  }
  gHost.virt = static_cast<uint8_t *> (gHost.dma->getBytesNoCopy ());
  IOByteCount contiguous = 0;
  gHost.phys = gHost.dma->getPhysicalSegment (0, &contiguous, kIOMemoryMapperNone);
  gRootDiagnostic.dma = gHost.phys;
  gRootDiagnostic.contiguous = contiguous;
  if (!gHost.virt || !gHost.phys || (gHost.phys & 4095) || contiguous < kDmaBytes ||
      (!(read32 (gHost.hc, 0) & 0x01000000) && gHost.phys + kDmaBytes > 0x100000000ULL)) {
    *why = "DMA address/contiguity";
    return false;
  }
  bzero (gHost.virt, kDmaBytes);
  cacheCivac (gHost.virt, kDmaBytes);
  uint32_t report[3] = { 0, 0, 0 };
  gRootDiagnostic.stage = "SMMU and request list";
  if (!hostStopQueue (why)) return false;
  smmuBypassStream (0x60, gHost.smmuMap, report, gHost.phys, kDmaBytes);
  gHost.smmu = gHost.smmuMap->getVirtualAddress ();
  uint32_t idr1 = read32 (gHost.smmu, 0x24);
  // native-ufs-smmu=0 configured no bank: leave cb unset so the fault snapshot skips it.
  gHost.cb = report[0] == 0xffffffffU ? 0 : gHost.smmu + ((1U << (((idr1 >> 28) & 7) + 1)) + (report[0] >> 16)) * 4096;
  if (gRootDiagnosticEnabled) {
    gRootDiagnostic.gfsrBefore = read32 (gHost.smmu, 0x48);
    gRootDiagnostic.smmuId2 = read32 (gHost.smmu, 0x28);
    if (gHost.cb) {
      gRootDiagnostic.fsrBefore = read32 (gHost.cb, 0x58);
      gRootDiagnostic.cba2r = read32 (gHost.smmu, 0x1800 + 4 * (report[0] >> 16));
    } else {
      gRootDiagnostic.cbar = report[1];  // native-ufs-smmu=0: sCR0 in the cbar field
    }
  }
  gRootDiagnostic.stage = "link wake";
  if (const char *wake = uicWakeLink (gHost.hc)) {
    *why = wake;
    return false;
  }
  if (!hostStartQueue (why)) return false;
  gRootDiagnostic.stage = "NOP OUT";
  // NOP OUT proves the transport before touching the SCSI layer.
  if (hostNop () != kIOReturnSuccess) {
    gHost.ready = false;
    *why = "NOP OUT";
    return false;
  }
  uint32_t power = 0;
  gRootDiagnostic.stage = "power mode query";
  if (hostQueryRead (0x03, 0x02, &power) != kIOReturnSuccess) {
    gHost.ready = false;
    *why = "power mode query";
    return false;
  }
  gRootDiagnostic.power = power;
  if ((power & 0xff) != 0x11) {
    gRootDiagnostic.stage = "device wake";
    // START STOP UNIT, power condition ACTIVE, to the UFS Device well-known LU (as Linux resumes).
    uint8_t ssu[6] = { 0x1b, 0, 0, 0, 0x10, 0 };
    uint32_t scsi = 0;
    if (hostScsi (0xd0, ssu, 6, false, 0, 500000, &scsi) != kIOReturnSuccess) {
      gHost.ready = false;
      *why = "wake (START STOP UNIT)";
      return false;
    }
    IOSleep (50);
  }
  gRootDiagnostic.stage = "LUN ready";
  for (unsigned attempt = 0; attempt < 20; attempt++) {
    uint8_t tur[6] = { 0, 0, 0, 0, 0, 0 };
    uint32_t scsi = 0;
    if (hostScsi (0, tur, 6, false, 0, 200000, &scsi) == kIOReturnSuccess) {
      gHost.ready = true;
      return true;
    }
    if (gHost.poisoned) break;
    IOSleep (10);
  }
  gHost.ready = false;
  *why = "LUN 0 not ready";
  return false;
}
}

namespace {
static uint32_t be32w (const uint8_t *at)
{
  return (uint32_t (at[0]) << 24) | (uint32_t (at[1]) << 16) | (uint32_t (at[2]) << 8) | at[3];
}

#include "RootLayout.h"
#include "RootWindowRead.h"
#include "RootPublication.h"

}

// ---- Persistent Data store window (sheng-data-persist) ----------------------------------------------------------
// The only part of this driver that ever writes. The consumer (NativeRamBlock's overlay) asks for a window of the given
// size at the END of the userdata partition. Mode 1 (boot argument sheng-data-persist=1) only reads: it proves the window and
// lets the consumer inspect its header. Mode 2 additionally opens the write window. A window is refused unless it lies inside
// the partition, clear of the flashed root image plus a 4 MiB guard, and is at most a quarter of the partition.
namespace {
struct StoreGeometry {
  bool valid;
  uint64_t first, last, imageBytes, entriesLba;
  uint32_t headerCrc, entriesCrc, entryCount;
};
StoreGeometry gStoreGeometry;
uint64_t gStoreRegionFirst, gStoreRegionBlocks;
// The diagnostic log (sheng-log=1): always the last 32 MiB of userdata, so the Data store's place does not depend on logging.
constexpr uint64_t kLogReserveBlocks = 8192;
// The log's export region: the 256 MiB just below the log window (the render server's pipeline caches, kits/sheng BootLog.c). It is
// part of the log's write window, so the store ends below both.
constexpr uint64_t kExportBlocks = 65536;
uint64_t gLogRegionFirst, gLogRegionBlocks;
// The reserve at the end of userdata that the Data store stays clear of: the log and its export region sit inside it (sheng-log=1), the rest
// is unused. sheng-log-reserve=<MiB>, default 1024; 0 gives all the room to Data and is only accepted with the log off. The store's place
// depends on it, so an image keeps one value for its whole life (a different value moves the store: the old one is read as blank).
constexpr uint32_t kDefaultReserveMiB = 1024;
static uint64_t reserveBlocks (void)
{
  static int64_t cached = -1;
  if (cached < 0) {
    uint32_t mib = kDefaultReserveMiB;
    if (!PE_parse_boot_argn ("sheng-log-reserve", &mib, sizeof (mib)) || mib > 16384) mib = kDefaultReserveMiB;
    cached = static_cast<int64_t> (mib) * 256;   // 4096-byte blocks
  }
  return static_cast<uint64_t> (cached);
}

static unsigned storeMode (void)
{
  static int cached = -1;
  if (cached < 0) {
    uint32_t value = 0;
    if (!PE_parse_boot_argn ("sheng-data-persist", &value, sizeof (value)) || value > 2) value = 0;
    cached = static_cast<int> (value);
  }
  return static_cast<unsigned> (cached);
}
}

extern "C" unsigned native_ufs_store_mode (void) { return storeMode (); }

// Returns 1 and the first absolute 4096-byte LBA of the window, 0 on refusal (reason in *why, may be null).
extern "C" int native_ufs_store_open (uint64_t blocks, uint64_t *firstLba, const char **why)
{
  const char *reason = "";
  int ok = 0;
  if (!storeMode ()) reason = "off";
  else if (!gStoreGeometry.valid || !gHost.ready) reason = "no root layout";
  else if (gStoreRegionBlocks) reason = "already open";
  else {
    uint64_t partition = gStoreGeometry.last - gStoreGeometry.first + 1;
    uint64_t imageBlocks = (gStoreGeometry.imageBytes + 4095) / 4096;
    const uint64_t reserve = reserveBlocks ();
    if (!blocks || reserve >= partition || blocks > partition - reserve) reason = "size";
    else if (partition - blocks - reserve < imageBlocks + 1024) reason = "overlaps the root image";
    else {
      // The reserve at the end of the partition belongs to the diagnostic log (its last 32 MiB, with the export region below them);
      // the store ends just below it.
      uint64_t first = gStoreGeometry.last + 1 - reserve - blocks;
      if (storeMode () == 2 && !hostStoreOpen (first, blocks)) reason = "window refused";
      else {
        gStoreRegionFirst = first;
        gStoreRegionBlocks = blocks;
        if (firstLba) *firstLba = first;
        ok = 1;
      }
    }
  }
  if (why) *why = reason;
  return ok;
}

extern "C" int native_ufs_store_read (uint64_t rel, uint32_t blocks, void *dst)
{
  if (!gStoreRegionBlocks || !dst || !blocks || rel >= gStoreRegionBlocks || blocks > gStoreRegionBlocks - rel) return 0;
  while (blocks) {
    uint32_t chunk = blocks > kDataMax / 4096 ? static_cast<uint32_t> (kDataMax / 4096) : blocks;
    if (hostRead4k (0, gStoreRegionFirst + rel, chunk, dst) != kIOReturnSuccess) return 0;
    dst = static_cast<uint8_t *> (dst) + chunk * 4096ULL;
    rel += chunk;
    blocks -= chunk;
  }
  return 1;
}

extern "C" int native_ufs_store_write (uint64_t rel, uint32_t blocks, const void *src)
{
  if (storeMode () != 2 || !gStoreRegionBlocks || !src || !blocks || rel >= gStoreRegionBlocks ||
      blocks > gStoreRegionBlocks - rel) return 0;
  while (blocks) {
    uint32_t chunk = blocks > kDataMax / 4096 ? static_cast<uint32_t> (kDataMax / 4096) : blocks;
    // Forced unit access: the block is on the medium when the command completes, so the overlay needs no cache flush.
    if (hostWrite4k (0, gStoreRegionFirst + rel, chunk, src, true) != kIOReturnSuccess) return 0;
    src = static_cast<const uint8_t *> (src) + chunk * 4096ULL;
    rel += chunk;
    blocks -= chunk;
  }
  return 1;
}

extern "C" int native_ufs_store_sync (void)
{
  return storeMode () == 2 && gStoreRegionBlocks && hostSyncCache () == kIOReturnSuccess;
}

// ---- Diagnostic log window (sheng-log=1) --------------------------------------------------------------------------
// The board's log writer (kits/sheng BootLog.c) gets the last kLogReserveBlocks of userdata and the kExportBlocks below them, refused
// unless the partition holds them clear of the flashed root image plus a 4 MiB guard. Off without the boot argument.
static unsigned logMode (void)
{
  static int cached = -1;
  if (cached < 0) {
    uint32_t value = 0;
    if (!PE_parse_boot_argn ("sheng-log", &value, sizeof (value)) || value > 1) value = 0;
    cached = static_cast<int> (value);
  }
  return static_cast<unsigned> (cached);
}

// Returns 1 with the window's first absolute LBA and size in 4096-byte blocks, 0 on refusal (reason in *why, may be null).
extern "C" int native_ufs_log_open (uint64_t *firstLba, uint64_t *blocks, const char **why)
{
  const char *reason = "";
  int ok = 0;
  if (!logMode ()) reason = "off";
  else if (!gStoreGeometry.valid || !gHost.ready) reason = "no root layout";
  else if (gLogRegionBlocks) reason = "already open";
  else {
    uint64_t partition = gStoreGeometry.last - gStoreGeometry.first + 1;
    uint64_t imageBlocks = (gStoreGeometry.imageBytes + 4095) / 4096;
    if (reserveBlocks () < kLogReserveBlocks + kExportBlocks) reason = "reserve too small for the log";
    else if (partition - reserveBlocks () < imageBlocks + 1024) reason = "overlaps the root image";
    else {
      uint64_t first = gStoreGeometry.last + 1 - kLogReserveBlocks;
      // One write window covers the export region and the log: [first - kExportBlocks, first + kLogReserveBlocks).
      if (!hostLogOpen (first - kExportBlocks, kExportBlocks + kLogReserveBlocks)) reason = "window refused";
      else {
        gLogRegionFirst = first;
        gLogRegionBlocks = kLogReserveBlocks;
        if (firstLba) *firstLba = first;
        if (blocks) *blocks = kLogReserveBlocks;
        ok = 1;
      }
    }
  }
  if (why) *why = reason;
  return ok;
}

extern "C" int native_ufs_log_write (uint64_t rel, uint32_t blocks, const void *src)
{
  if (!gLogRegionBlocks || !src || !blocks || rel >= gLogRegionBlocks || blocks > gLogRegionBlocks - rel) return 0;
  while (blocks) {
    uint32_t chunk = blocks > kDataMax / 4096 ? static_cast<uint32_t> (kDataMax / 4096) : blocks;
    if (hostWrite4k (0, gLogRegionFirst + rel, chunk, src) != kIOReturnSuccess) return 0;
    src = static_cast<const uint8_t *> (src) + chunk * 4096ULL;
    rel += chunk;
    blocks -= chunk;
  }
  return 1;
}

// The export region below the log window: its size in blocks once the log is open, else 0; writes at a block offset inside it.
extern "C" uint64_t native_ufs_export_blocks (void) { return gLogRegionBlocks ? kExportBlocks : 0; }

extern "C" int native_ufs_export_write (uint64_t rel, uint32_t blocks, const void *src)
{
  if (!gLogRegionBlocks || !src || !blocks || rel >= kExportBlocks || blocks > kExportBlocks - rel) return 0;
  const uint64_t base = gLogRegionFirst - kExportBlocks;
  while (blocks) {
    uint32_t chunk = blocks > kDataMax / 4096 ? static_cast<uint32_t> (kDataMax / 4096) : blocks;
    if (hostWrite4k (0, base + rel, chunk, src) != kIOReturnSuccess) return 0;
    src = static_cast<const uint8_t *> (src) + chunk * 4096ULL;
    rel += chunk;
    blocks -= chunk;
  }
  return 1;
}

extern "C" int native_ufs_log_sync (void)
{
  return gLogRegionBlocks && hostSyncCache () == kIOReturnSuccess;
}

// Re-read the GPT header and entry array and compare their CRCs with what was recorded at root start. 0 = unchanged.
extern "C" unsigned native_ufs_store_gpt_check (void)
{
  if (!gStoreGeometry.valid || !gHost.ready) return 1;
  static uint8_t block[4096];
  if (hostRead4k (0, 1, 1, block) != kIOReturnSuccess) return 2;
  uint32_t headerBytes = le32 (block + 12);
  if (headerBytes < 92 || headerBytes > 4096 || rootCrc32 (block, headerBytes, true) != le32 (block + 16) ||
      le32 (block + 16) != gStoreGeometry.headerCrc) return 3;
  uint32_t blocks = (gStoreGeometry.entryCount * 128 + 4095) / 4096;
  static uint8_t entries[4096 * 4];
  if (blocks > 4 || hostRead4k (0, gStoreGeometry.entriesLba, blocks, entries) != kIOReturnSuccess) return 4;
  return rootCrc32 (entries, gStoreGeometry.entryCount * 128) == gStoreGeometry.entriesCrc ? 0 : 5;
}

// One read-only window of the root image as a block device: 512-byte sectors on top of 4096-byte
// UFS blocks, so the unchanged dmg disk images (GPT with 512-byte sectors) parse as they do on
// the virtio path.
// erhai --probe-only builds (scripts/build-arm-driver.py) leave out the block device and the root
// publication: their IOBlockStorageDevice base resolves only through the NativeVirtioBlock bindings.
#if !(defined(NATIVE_UFS_PROBE_ONLY) && NATIVE_UFS_PROBE_ONLY)
class NativeUfsBlock : public IOBlockStorageDevice {
  OSDeclareDefaultStructors (NativeUfsBlock)
  uint64_t absolute = 0;      // byte offset of the window on LUN 0
  uint64_t bytes = 0;
  char label[32] = {};
  uint8_t *bounce = nullptr;
  IOLock *windowLock = nullptr;
  bool online = false;
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
  struct vr_view verified = {};
  vm_offset_t verifiedStorage = 0;
  vm_size_t verifiedStorageBytes = 0;
  bool configureVerification ();
#endif
public:
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
  bool authenticatesVolume (const char *uuid, uint8_t *manifestDigest = nullptr) const;
  bool signedVolumeUuid (char out[37]) const;
#endif
  const char *windowLabel () const { return label; }
  bool configure (const char *name, uint64_t absoluteOffset, uint64_t size);
  bool start (IOService *provider) override;
  void free () override;
  IOReturn doEjectMedia () override { return kIOReturnUnsupported; }
  IOReturn doFormatMedia (UInt64) override { return kIOReturnNotWritable; }
  UInt32 doGetFormatCapacities (UInt64 *, UInt32) const override { return 0; }
  char *getVendorString () override { return const_cast<char *> ("Native"); }
  char *getProductString () override { return label; }
  char *getRevisionString () override { return const_cast<char *> ("1.0"); }
  char *getAdditionalDeviceInfoString () override { return const_cast<char *> ("UFS LUN 0 userdata window, read-only"); }
  IOReturn reportBlockSize (UInt64 *value) override { *value = 512; return kIOReturnSuccess; }
  IOReturn reportEjectability (bool *value) override { *value = false; return kIOReturnSuccess; }
  IOReturn reportMaxValidBlock (UInt64 *value) override { *value = bytes / 512 - 1; return kIOReturnSuccess; }
  IOReturn reportMediaState (bool *present, bool *changed) override {
    *present = online; if (changed) *changed = false; return kIOReturnSuccess;
  }
  IOReturn reportRemovability (bool *value) override { *value = false; return kIOReturnSuccess; }
  IOReturn reportWriteProtection (bool *value) override { *value = true; return kIOReturnSuccess; }
  IOReturn doSynchronizeCache () override { return online ? kIOReturnSuccess : kIOReturnNotReady; }
  IOReturn doSynchronize (UInt64, UInt64, IOOptionBits) override { return doSynchronizeCache (); }
  IOReturn getWriteCacheState (bool *value) override { *value = false; return kIOReturnSuccess; }
  IOReturn setWriteCacheState (bool) override { return kIOReturnUnsupported; }
  IOReturn doAsyncReadWrite (IOMemoryDescriptor *, UInt64, UInt64, IOStorageAttributes *, IOStorageCompletion *) override;
};
OSDefineMetaClassAndStructors (NativeUfsBlock, IOBlockStorageDevice)

#endif

extern "C" {
volatile uint32_t native_ufs_blocks_published = 0;
volatile uint64_t native_ufs_block_reads = 0;
volatile uint64_t native_ufs_block_failures = 0;
}

static char gRootDiagnosticText[2500];
static char gRootMediaText[1000];
// Passive diagnostic reader: cached software values only. It must remain safe
// when called from an IRQ while the transport is busy: no locks, allocations,
// MMIO reads, queue resets, or changes to the command/trust state. Fields can
// represent adjacent updates; this is explicitly not an atomic HW snapshot.
extern "C" void native_ufs_progress_text (char *out, size_t size)
{
  UfsRootDiagnostics sample = gRootDiagnostic;
  sample.published = native_ufs_blocks_published;
  sample.reads = native_ufs_block_reads;
  sample.failures = native_ufs_block_failures;
  formatUfsRootDiagnostics (out, size, sample, "cached values; not a new HW fault sample", "UFS CACHED SNAPSHOT");
}

static void rootDiagnosticFailure (const char *reason)
{
  // Kept even when the panic diagnostic is off, so the boot page can say why nothing was published.
  native_ufs_root_failure = reason;
  if (!gRootDiagnosticEnabled) return;
  gRootDiagnostic.published = native_ufs_blocks_published;
  gRootDiagnostic.reads = native_ufs_block_reads;
  gRootDiagnostic.failures = native_ufs_block_failures;
  formatUfsRootDiagnostics (gRootDiagnosticText, sizeof (gRootDiagnosticText), gRootDiagnostic, reason);
  strlcat (gRootDiagnosticText, gRootMediaText, sizeof (gRootDiagnosticText));
  panic ("%s", gRootDiagnosticText);
}

#if !(defined(NATIVE_UFS_PROBE_ONLY) && NATIVE_UFS_PROBE_ONLY)
bool NativeUfsBlock::configure (const char *name, uint64_t absoluteOffset, uint64_t size)
{
  if (!name || !ufsWindowGeometry (absoluteOffset, size)) {
    return false;
  }
  strlcpy (label, name, sizeof (label));
  absolute = absoluteOffset;
  bytes = size;
  windowLock = IOLockAlloc ();
  if (!windowLock) return false;
  bounce = static_cast<uint8_t *> (IOMalloc (kDataMax));
  if (!bounce) {
    return false;
  }
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
  // Reads are served only after each 4096-byte integrity block verifies against the owner-signed
  // policy; without a matching policy the device is never published.
  return configureVerification ();
#else
  return true;
#endif
}

// Time spent hashing/verifying and reading from the UFS transport, in generic-timer ticks (diagnostic only).
// Outside the verified-block block: the read path uses them in both builds (erhai --probe-only).
volatile uint64_t native_ufs_verify_ticks = 0, native_ufs_read_ticks = 0;
static inline uint64_t timerTicks (void) {uint64_t v; __asm__ volatile ("isb\n\tmrs %0, cntpct_el0" : "=r" (v)); return v;}

#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
volatile uint64_t native_ufs_verified_blocks = 0;
volatile uint32_t native_ufs_integrity_failures = 0;

bool NativeUfsBlock::configureVerification ()
{
  gRootDiagnostic.stage = "policy selection";
  gRootDiagnostic.windowBytes = bytes;
  gRootDiagnostic.policyCount = verified_root_policy_count;
  gRootDiagnostic.verify = 0xffffffff;
  // Select the one policy whose signed image size equals this window; two matches are refused.
  const uint8_t *manifest = nullptr;
  uint64_t manifestBytes = 0;
  if (!verified_root_policy_count || verified_root_policy_count > 16) {
    gRootDiagnostic.stage = "policy count invalid";
    return false;
  }
  for (uint64_t index = 0; index < verified_root_policy_count; ++index) {
    const NativeVerifiedBlockPolicy &policy = verified_root_policies[index];
    if (!policy.manifest || policy.manifestBytes < VR_HEADER_BYTES + VR_SIGNATURE_BYTES) {
      gRootDiagnostic.stage = "policy envelope invalid";
      return false;
    }
    uint64_t imageBytes = 0;
    for (unsigned i = 0; i < 8; ++i) {
      imageBytes |= static_cast<uint64_t> (policy.manifest[24 + i]) << (8 * i);
    }
    if (imageBytes != bytes) {
      continue;
    }
    if (manifest) {
      gRootDiagnostic.stage = "duplicate capacity-matching policy";
      return false;
    }
    manifest = policy.manifest;
    manifestBytes = policy.manifestBytes;
  }
  if (!manifest) {
    gRootDiagnostic.stage = "no capacity-matching policy";
    return false;
  }
  gRootDiagnostic.stage = "policy storage";
  vm_size_t tableBytes = round_page (static_cast<vm_size_t> (manifestBytes));
  if (tableBytes < manifestBytes || tableBytes > UINT64_MAX - 4096) {
    gRootDiagnostic.stage = "policy size overflow";
    return false;
  }
  verifiedStorageBytes = tableBytes + 4096;
  gRootDiagnostic.stage = "policy allocation";
  if (kmem_alloc (kernel_map, &verifiedStorage, verifiedStorageBytes,
                  static_cast<kma_flags_t> (KMA_KOBJECT | KMA_DATA), VM_KERN_MEMORY_SECURITY) != KERN_SUCCESS) {
    return false;
  }
  memcpy (reinterpret_cast<void *> (verifiedStorage), manifest, manifestBytes);
  uint8_t *key = reinterpret_cast<uint8_t *> (verifiedStorage + tableBytes);
  memcpy (key, verified_root_key, VR_KEY_BYTES);
  gRootDiagnostic.stage = "policy read-only protection";
  if (vm_map_protect (kernel_map, verifiedStorage, verifiedStorage + verifiedStorageBytes,
                      VM_PROT_READ, TRUE) != KERN_SUCCESS) {
    return false;
  }
  gRootDiagnostic.stage = "owner signature and hash table";
  int status = vr_open (reinterpret_cast<const uint8_t *> (verifiedStorage), manifestBytes, key, 1,
                        &vr_xnu_crypto, &verified);
  gRootDiagnostic.verify = static_cast<uint32_t> (status);
  return status == VR_OK && verified.image_bytes == bytes;
}

bool NativeUfsBlock::authenticatesVolume (const char *uuid, uint8_t *manifestDigest) const
{
  if (!uuid || !online || !verifiedStorage || !verified.hashes) {
    return false;
  }
  static const char hex[] = "0123456789ABCDEF";
  char expected[37];
  unsigned at = 0;
  for (unsigned i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      expected[at++] = '-';
    }
    expected[at++] = hex[verified.volume_uuid[i] >> 4];
    expected[at++] = hex[verified.volume_uuid[i] & 15];
  }
  expected[at] = 0;
  if (strcmp (uuid, expected)) {
    return false;
  }
  if (manifestDigest) {
    // Hash only the authenticated envelope, excluding allocation padding and the key.
    const uint64_t envelope = VR_HEADER_BYTES + VR_SIGNATURE_BYTES + verified.block_count * 32;
    SHA384_CTX context;
    SHA384_Init (&context);
    SHA384_Update (&context, reinterpret_cast<const void *> (verifiedStorage), envelope);
    SHA384_Final (manifestDigest, &context);
  }
  return true;
}

bool NativeUfsBlock::signedVolumeUuid (char out[37]) const
{
  if (!verifiedStorage || !verified.hashes) {
    return false;
  }
  static const char hex[] = "0123456789ABCDEF";
  unsigned at = 0;
  for (unsigned i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      out[at++] = '-';
    }
    out[at++] = hex[verified.volume_uuid[i] >> 4];
    out[at++] = hex[verified.volume_uuid[i] & 15];
  }
  out[at] = 0;
  return true;
}

// Called from the root authorization query in NativeVirtioBlock: -1 when `provider` is not a
// UFS window, otherwise 1 if its signed volume UUID equals `uuid`, else 0.
extern "C" int native_ufs_block_authenticates (IOService *provider, const char *uuid, uint8_t *digest)
{
  NativeUfsBlock *block = OSDynamicCast (NativeUfsBlock, provider);
  if (!block) {
    return -1;
  }
  return block->authenticatesVolume (uuid, digest) ? 1 : 0;
}
#endif

bool NativeUfsBlock::start (IOService *provider)
{
  if (!bounce || !windowLock || !IOBlockStorageDevice::start (provider)) {
    return false;
  }
  online = true;
  registerService ();
  return true;
}

IOReturn NativeUfsBlock::doAsyncReadWrite (IOMemoryDescriptor *buffer, UInt64 block, UInt64 count,
                                           IOStorageAttributes *, IOStorageCompletion *completion)
{
  if (!buffer || !completion || !completion->action || !count || block >= bytes / 512 ||
      count > bytes / 512 - block || buffer->getLength () < count * 512) {
    return kIOReturnBadArgument;
  }
  if (buffer->getDirection () != kIODirectionIn) {
    return kIOReturnNotWritable;
  }
  if (!online) {
    return kIOReturnNotReady;
  }
  struct Operations {
    IOLock *mutex;
    IOMemoryDescriptor *buffer;
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
    const vr_view *view;
#endif
    void lock () { IOLockLock (mutex); }
    void unlock () { IOLockUnlock (mutex); }
    IOReturn read (uint64_t lba, uint32_t blocks, void *out) {
      uint64_t t0 = timerTicks ();
      IOReturn r = hostRead4k (0, lba, blocks, out);
      __atomic_fetch_add (&native_ufs_read_ticks, timerTicks () - t0, __ATOMIC_RELAXED);
      return r;
    }
    IOReturn verify (uint64_t index, const void *data, size_t length) {
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
      uint64_t t0 = timerTicks ();
      int status = vr_verify_block (view, index, data, length, &vr_xnu_crypto);
      __atomic_fetch_add (&native_ufs_verify_ticks, timerTicks () - t0, __ATOMIC_RELAXED);
      if (status != VR_OK) {
        gRootDiagnostic.stage = "read block integrity";
        gRootDiagnostic.verify = static_cast<uint32_t> (status);
        __atomic_fetch_add (&native_ufs_integrity_failures, 1, __ATOMIC_RELAXED);
        return kIOReturnNotPrivileged;
      }
      __atomic_fetch_add (&native_ufs_verified_blocks, 1, __ATOMIC_RELAXED);
      if (boot_progress_poll) boot_progress_poll ();
#else
      (void) index; (void) data; (void) length;
#endif
      return kIOReturnSuccess;
    }
    uint64_t copy (uint64_t offset, const void *data, uint64_t length) {
      uint64_t copied = buffer->writeBytes (offset, data, length);
      if (copied == length) __atomic_fetch_add (&native_ufs_block_reads, 1, __ATOMIC_RELAXED);
      return copied;
    }
  } operations = { windowLock, buffer
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
    , &verified
#endif
  };
  UfsWindowResult outcome = ufsReadWindow (operations, absolute, bytes, block, count, bounce);
  IOReturn result = outcome.status;
  uint64_t done = outcome.done;
  if (result != kIOReturnSuccess) {
    __atomic_fetch_add (&native_ufs_block_failures, 1, __ATOMIC_RELAXED);
    gRootDiagnostic.result = static_cast<uint32_t> (result);
    rootDiagnosticFailure ("root window read failed");
  }
  completion->action (completion->target, completion->parameter, result, done);
  return kIOReturnSuccess;
}

void NativeUfsBlock::free ()
{
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
  if (verifiedStorage) {
    kmem_free (kernel_map, verifiedStorage, verifiedStorageBytes);
    verifiedStorage = 0;
  }
#endif
  if (bounce) {
    IOFree (bounce, kDataMax);
    bounce = nullptr;
  }
  if (windowLock) {
    IOLockFree (windowLock);
    windowLock = nullptr;
  }
  IOBlockStorageDevice::free ();
}

// Ordered publication of the root windows. The original owner-trust code resolves the SystemOS
// volume by UUID immediately after the root is mounted, so SystemOS must already have published its
// volume media by then; the OS window (whose volume is the root being waited for) goes last.
static NativeUfsBlock *gPendingDevice[4];
static unsigned gPending;
static bool gPendingAttached[4];
static char gPendingUuid[4][37];
static UfsRootPlan gPublicationPlan;
static NativeUfs *gPendingProvider;

static bool mediaWithUuidExists (const char *uuid, NativeUfsBlock *window)
{
  OSDictionary *matching = IOService::serviceMatching ("IOMedia");
  OSDictionary *properties = OSDictionary::withCapacity (1);
  OSString *wanted = OSString::withCString (uuid);
  bool found = false;
  if (matching && properties && wanted && properties->setObject ("UUID", wanted) &&
      matching->setObject ("IOPropertyMatch", properties)) {
    OSIterator *iterator = IOService::getMatchingServices (matching);
    if (iterator) {
      for (unsigned matches = 0; matches < 64 && !found; ++matches) {
        IORegistryEntry *media = OSDynamicCast (IORegistryEntry, iterator->getNextObject ());
        if (!media) break;
        IORegistryIterator *parents = IORegistryIterator::iterateOver (
          media, gIOServicePlane, kIORegistryIterateRecursively | kIORegistryIterateParents);
        if (parents) {
          found = ufsMediaHasAncestor (*parents, window);
          parents->release ();
        }
      }
      iterator->release ();
    }
  }
  OSSafeReleaseNULL (wanted);
  OSSafeReleaseNULL (properties);
  OSSafeReleaseNULL (matching);
  return found;
}

static void captureMissingMedia (const char *uuid)
{
  int used = snprintf (gRootMediaText, sizeof (gRootMediaText), "Waiting for signed UUID %s\n", uuid);
  OSDictionary *matching = IOService::serviceMatching ("IOMedia");
  OSIterator *iterator = matching ? IOService::getMatchingServices (matching) : nullptr;
  unsigned count = 0;
  while (iterator && used < int (sizeof (gRootMediaText)) - 180 && count++ < 8) {
    IOService *media = OSDynamicCast (IOService, iterator->getNextObject ());
    if (!media) break;
    OSString *id = OSDynamicCast (OSString, media->getProperty ("UUID"));
    OSString *bsd = OSDynamicCast (OSString, media->getProperty (kIOBSDNameKey));
    OSNumber *size = OSDynamicCast (OSNumber, media->getProperty ("Size"));
    used += snprintf (gRootMediaText + used, sizeof (gRootMediaText) - used,
                      "media %.24s bytes=%llx uuid=%.36s\n",
                      bsd ? bsd->getCStringNoCopy () : "-", size ? size->unsigned64BitValue () : 0ULL,
                      id ? id->getCStringNoCopy () : "-");
  }
  OSSafeReleaseNULL (iterator);
  OSSafeReleaseNULL (matching);
}

// Used only for objects that were never started/published. Started objects
// retain their owner references even on a later failure; clients can have I/O.
static void discardPendingWindow (unsigned index)
{
  NativeUfsBlock *device = gPendingDevice[index];
  if (!device) return;
  if (gPendingAttached[index]) device->detach (gPendingProvider);
  gPendingAttached[index] = false;
  gPendingDevice[index] = nullptr;
  device->release ();
}

static void publishThread (void *, wait_result_t)
{
  struct Operations {
    bool start (unsigned index) {
      NativeUfsBlock *device = gPendingDevice[index];
      gRootDiagnostic.stage = "root window service start";
      gRootDiagnostic.publicationPhase = static_cast<unsigned> (UfsRootPhase::Start);
      gRootDiagnostic.publicationWindow = index;
      if (!device->start (gPendingProvider)) return false;
      native_ufs_blocks_published = native_ufs_blocks_published + 1;
      IOLog ("NativeUfs: published %s\n", device->windowLabel ());
      return true;
    }
    bool wait (unsigned index) {
      NativeUfsBlock *device = gPendingDevice[index];
      const char *uuid = gPendingUuid[index];
      gRootDiagnostic.stage = "media publication";
      gRootDiagnostic.publicationPhase = static_cast<unsigned> (UfsRootPhase::Media);
      gRootDiagnostic.publicationWindow = index;
      bool ready = false;
      // Diagnostic mode affects reporting only, never the dependency gate.
      for (unsigned tick = 0; tick <= 300; ++tick) {
        ready = mediaWithUuidExists (uuid, device);
        if (ready || tick == 300) break;
        IOSleep (100);
      }
      IOLog ("NativeUfs: %s volume %s %s\n", device->windowLabel (), uuid, ready ? "ready" : "not ready");
      if (!ready) captureMissingMedia (uuid);
      return ready;
    }
    void discard (unsigned index) { discardPendingWindow (index); }
  } operations;
  UfsRootPublicationResult result = ufsPublishRootWindows (operations, gPublicationPlan);
  if (result.phase != UfsRootPhase::Complete) {
    gRootDiagnostic.result = result.phase == UfsRootPhase::Start ? kIOReturnIOError : kIOReturnTimeout;
    const char *reason = result.phase == UfsRootPhase::Start ? "root window service start failed" :
      (!strcmp (gPendingDevice[result.index]->windowLabel (), "SystemOS") ?
       "SystemOS signed volume not found" : "signed root window volume not found");
    IOLog ("NativeUfs: root publisher stopped at window %u; published=%u\n", result.index, result.published);
    // Start failures have already released their unpublished object; do not
    // dereference it here. The media-failure object is deliberately retained.
    rootDiagnosticFailure (reason);
  }
  gPendingProvider->release ();  // Balanced with successful thread dispatch.
}

// Memory snapshot (native-ufs-probe=13): root mode as usual, then, after a delay, the kernel's own
// page counters on the panic screen. Observation only.
extern "C" {
extern unsigned int vm_page_free_count, vm_page_active_count, vm_page_inactive_count,
  vm_page_wire_count, vm_page_speculative_count, vm_page_purgeable_count;
extern uint32_t vm_page_pages;
extern unsigned int memorystatus_available_pages;
extern int nprocs;
}

static void statsThread (void *argument, wait_result_t)
{
  unsigned delay = static_cast<unsigned> (reinterpret_cast<uintptr_t> (argument));
  IOSleep (delay * 1000);
  panic ("NATIVE_UFS memory snapshot after %u s\n"
         "pages total=%u free=%u active=%u inactive=%u wired=%u spec=%u purgeable=%u\n"
         "available=%u max_mem=%llx procs=%d blocks=%llu\n",
         delay, vm_page_pages, vm_page_free_count, vm_page_active_count, vm_page_inactive_count,
         vm_page_wire_count, vm_page_speculative_count, vm_page_purgeable_count,
         memorystatus_available_pages, max_mem, nprocs, native_ufs_block_reads);
}

// Storage discovery report (native-ufs-probe=12): a separate thread waits for the original
// IOStorageFamily to publish IOMedia for the root windows, then shows what exists on the screen.
// It must not run inside the matching thread that is starting NativeUfs.
static char gMediaReport[3000];

static void mediaReportThread (void *, wait_result_t)
{
  unsigned count = 0;
  for (unsigned tick = 0; tick < 200; tick++) {      // up to 20 s
    OSDictionary *matching = IOService::serviceMatching ("IOMedia");
    OSIterator *iterator = matching ? IOService::getMatchingServices (matching) : nullptr;
    count = 0;
    if (iterator) {
      while (iterator->getNextObject ()) {
        count++;
      }
      iterator->release ();
    }
    if (matching) {
      matching->release ();
    }
    if (count >= 4) {
      break;
    }
    IOSleep (100);
  }
  IOSleep (500);
  int used = snprintf (gMediaReport, sizeof (gMediaReport),
                       "NATIVE_UFS media report: published=%u reads=%llu failures=%llu media=%u\n",
                       native_ufs_blocks_published, native_ufs_block_reads, native_ufs_block_failures, count);
  OSDictionary *matching = IOService::serviceMatching ("IOMedia");
  OSIterator *iterator = matching ? IOService::getMatchingServices (matching) : nullptr;
  while (iterator && used < int (sizeof (gMediaReport)) - 200) {
    IOService *media = OSDynamicCast (IOService, iterator->getNextObject ());
    if (!media) {
      break;
    }
    OSString *uuid = OSDynamicCast (OSString, media->getProperty ("UUID"));
    OSString *bsd = OSDynamicCast (OSString, media->getProperty (kIOBSDNameKey));
    OSString *content = OSDynamicCast (OSString, media->getProperty ("Content"));
    OSNumber *size = OSDynamicCast (OSNumber, media->getProperty ("Size"));
    used += snprintf (gMediaReport + used, sizeof (gMediaReport) - used, "%s %s size=%llx uuid=%s\n",
                      bsd ? bsd->getCStringNoCopy () : "-", content ? content->getCStringNoCopy () : "-",
                      size ? size->unsigned64BitValue () : 0ULL, uuid ? uuid->getCStringNoCopy () : "-");
  }
  if (iterator) {
    iterator->release ();
  }
  if (matching) {
    matching->release ();
  }
  panic ("%s", gMediaReport);
}

#endif

bool NativeUfs::start (IOService *provider)
{
  unsigned probe = 0, rootMode = 0;
  PE_parse_boot_argn ("native-ufs-probe", &probe, sizeof (probe));
  PE_parse_boot_argn ("native-ufs-root", &rootMode, sizeof (rootMode));
  native_ufs_probe_requested = probe != 0;
  // Default: match for observability only, never touch the controller. Hardware work runs once,
  // from the root-device personality; the ufshc nub match stays observation-only.
  if ((!probe && !rootMode) || !OSDynamicCast (IOPlatformExpertDevice, provider)) {
    return false;
  }
  unsigned diagnostic = 0;
  PE_parse_boot_argn ("native-ufs-diagnostics", &diagnostic, sizeof (diagnostic));
  gRootDiagnosticEnabled = diagnostic == 1;
  if (probe == 2) {
    inspect ();
  }
  if (probe == 8) {
    inspectContextBanks ();
  }
  if (probe == 7) {
    inspectSmmu ();
  }
  if (probe == 15) {
    dumpSmmuStreams ();
  }
  if (probe == 16 || probe == 17) {
    dumpUicState (probe == 17);
  }
  if (probe == 6) {
    dumpFirmwareList ();
  }
  if ((probe >= 3 && probe <= 5) || probe == 9) {
    adoptAndRead (probe);
  }
  if (probe == 10) {
    // Read-only check before anything is flashed: LUN 0 GPT -> "userdata" -> its first block.
    const char *why = "";
    if (!hostBringUp (&why)) {
      // native-ufs-diagnostics=1: the full transport/SMMU snapshot instead of the bare reason.
      rootDiagnosticFailure (why);
      panic ("NATIVE_UFS root check: bring-up failed: %s", why);
    }
    RootLayout *layout = static_cast<RootLayout *> (IOMalloc (sizeof (RootLayout)));
    if (!layout || !findRootLayout (layout, &why)) {
      panic ("NATIVE_UFS root check: %s", why);
    }
    panic ("NATIVE_UFS root check\n"
           "userdata first=%llx last=%llx\n"
           "block0 magic %08x %08x ext4magic=%04x ext4blocks=%u\n"
           "manifest status=%u windows=%u",
           layout->userdataFirst, layout->userdataLast, layout->magic0, layout->magic1,
           layout->ext4Magic, layout->ext4Blocks, layout->manifestStatus, layout->windows);
  }
  if (probe == 11) {
    // After the root image is flashed: manifest, then each window's own GPT (sector 1 of the
    // attached dmg disk image carries "EFI PART"). Read-only.
    const char *why = "";
    if (!hostBringUp (&why)) {
      // native-ufs-diagnostics=1: the full transport/SMMU snapshot instead of the bare reason.
      rootDiagnosticFailure (why);
      panic ("NATIVE_UFS root windows: bring-up failed: %s", why);
    }
    RootLayout *layout = static_cast<RootLayout *> (IOMalloc (sizeof (RootLayout)));
    if (!layout || !findRootLayout (layout, &why)) {
      panic ("NATIVE_UFS root windows: %s", why);
    }
    uint32_t sig[4][2] = {};
    uint32_t seen[4] = {};
    for (uint32_t index = 0; index < layout->windows && index < 4; index++) {
      uint64_t absolute = layout->userdataFirst * 4096ULL + layout->window[index].offset;
      if (hostRead4k (0, absolute / 4096, 1, gScratch) == kIOReturnSuccess) {
        seen[index] = 1;
        sig[index][0] = le32 (gScratch + 512);
        sig[index][1] = le32 (gScratch + 516);
      }
    }
    panic ("NATIVE_UFS root windows\n"
           "userdata first=%llx last=%llx manifest status=%u windows=%u\n"
           "w0 %s off=%llx size=%llx gpt=%08x %08x read=%u\n"
           "w1 %s off=%llx size=%llx gpt=%08x %08x read=%u\n"
           "w0 sha %08x %08x %08x %08x\n"
           "w1 sha %08x %08x %08x %08x",
           layout->userdataFirst, layout->userdataLast, layout->manifestStatus, layout->windows,
           layout->window[0].name, layout->window[0].offset, layout->window[0].size, sig[0][0], sig[0][1], seen[0],
           layout->window[1].name, layout->window[1].offset, layout->window[1].size, sig[1][0], sig[1][1], seen[1],
           be32w (layout->window[0].sha256), be32w (layout->window[0].sha256 + 4), be32w (layout->window[0].sha256 + 8), be32w (layout->window[0].sha256 + 12),
           be32w (layout->window[1].sha256), be32w (layout->window[1].sha256 + 4), be32w (layout->window[1].sha256 + 8), be32w (layout->window[1].sha256 + 12));
  }
#if !(defined(NATIVE_UFS_PROBE_ONLY) && NATIVE_UFS_PROBE_ONLY)
  if (probe == 14) {
    // Immediate memory snapshot at root-device start, before the userspace that triggers jetsam.
    panic ("NATIVE_UFS early memory snapshot\n"
           "pages total=%u free=%u active=%u inactive=%u wired=%u spec=%u purgeable=%u\n"
           "available=%u max_mem=%llx procs=%d",
           vm_page_pages, vm_page_free_count, vm_page_active_count, vm_page_inactive_count,
           vm_page_wire_count, vm_page_speculative_count, vm_page_purgeable_count,
           memorystatus_available_pages, max_mem, nprocs);
  }
  if (probe == 13) {
    unsigned delay = 12;
    PE_parse_boot_argn ("native-ufs-stats-delay", &delay, sizeof (delay));
    if (!startRoot (provider)) {
      panic ("NATIVE_UFS memory snapshot: root start failed");
    }
    thread_t thread = nullptr;
    if (kernel_thread_start (statsThread, reinterpret_cast<void *> (static_cast<uintptr_t> (delay)), &thread) != KERN_SUCCESS) {
      panic ("NATIVE_UFS memory snapshot: cannot start the thread");
    }
    thread_deallocate (thread);
    return true;
  }
  if (probe == 12) {
    bool published = startRoot (provider);
    if (!published) {
      panic ("NATIVE_UFS media report: root start failed (blocks=%u)", native_ufs_blocks_published);
    }
    thread_t thread = nullptr;
    if (kernel_thread_start (mediaReportThread, nullptr, &thread) != KERN_SUCCESS) {
      panic ("NATIVE_UFS media report: cannot start the report thread");
    }
    thread_deallocate (thread);
    return true;
  }
  if (rootMode && !probe) {
    return startRoot (provider);
  }
#else
  if ((probe >= 12 && probe <= 14) || (rootMode && !probe)) {
    panic ("NATIVE_UFS: this is a --probe-only build; it cannot publish the root (probe=%u root=%u)", probe, rootMode);
  }
#endif
  return false;
}

// Boot the root image's windows as block devices. Soft-fails (logs, publishes nothing).
#if !(defined(NATIVE_UFS_PROBE_ONLY) && NATIVE_UFS_PROBE_ONLY)
bool NativeUfs::startRoot (IOService *provider)
{
  const char *why = "";
  native_ufs_root_step = 1;
  if (!hostBringUp (&why)) {
    rootDiagnosticFailure (why);
    IOLog ("NativeUfs: root bring-up failed: %s\n", why);
    return false;
  }
  native_ufs_root_step = 2;
  RootLayout *layout = static_cast<RootLayout *> (IOMalloc (sizeof (RootLayout)));
  if (!layout || !findRootLayout (layout, &why)) {
    rootDiagnosticFailure (layout ? why : "root layout allocation failed");
    IOLog ("NativeUfs: root layout failed: %s\n", why);
    if (layout) IOFree (layout, sizeof (RootLayout));
    return false;
  }
  native_ufs_root_step = 3;
  if (layout->manifestStatus != 0) {
    rootDiagnosticFailure ("root manifest rejected");
    IOLog ("NativeUfs: no valid root manifest in userdata (status %u, magic %08x %08x)\n",
           layout->manifestStatus, layout->magic0, layout->magic1);
    IOFree (layout, sizeof (RootLayout));
    return false;
  }
  gStoreGeometry = { true, layout->userdataFirst, layout->userdataLast, layout->imageBytes, layout->gptEntriesLba,
                     layout->gptHeaderCrc, layout->gptEntriesCrc, layout->gptEntryCount };
  const char *names[4] = {};
  for (unsigned i = 0; i < layout->windows; ++i) names[i] = layout->window[i].name;
  if (!ufsBuildRootPlan (names, layout->windows, gPublicationPlan)) {
    rootDiagnosticFailure ("root windows require distinct OS and SystemOS");
    IOFree (layout, sizeof (RootLayout));
    return false;
  }
  if (!IOService::start (provider)) {
    rootDiagnosticFailure ("root IOService start failed");
    IOFree (layout, sizeof (RootLayout));
    return false;
  }
  // Prepare all windows or publish none. Diagnostics never decide policy.
  gPending = 0;
  gPendingProvider = this;
  struct Operations {
    NativeUfs *owner;
    RootLayout *layout;
    bool prepare (unsigned index) {
      gRootDiagnostic.stage = "root window allocation/configuration";
      gRootDiagnostic.publicationPhase = static_cast<unsigned> (UfsRootPhase::Prepare);
      gRootDiagnostic.publicationWindow = index;
      gRootDiagnostic.windowBytes = layout->window[index].size;
      NativeUfsBlock *device = OSTypeAlloc (NativeUfsBlock);
      gPendingDevice[index] = device;
      gPendingAttached[index] = false;
      gPendingUuid[index][0] = 0;
      uint64_t absolute = layout->userdataFirst * 4096ULL + layout->window[index].offset;
      if (!device || !device->init (static_cast<OSDictionary *> (nullptr)) ||
          !device->configure (layout->window[index].name, absolute, layout->window[index].size)) return false;
      gRootDiagnostic.stage = "root window attachment";
      if (!device->attach (owner)) return false;
      gPendingAttached[index] = true;
      ++gPending;
      gRootDiagnostic.prepared = gPending;
      return true;
    }
    bool validate () {
      gRootDiagnostic.stage = "signed window identities";
      gRootDiagnostic.publicationPhase = static_cast<unsigned> (UfsRootPhase::Identity);
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
      for (unsigned i = 0; i < gPending; ++i) {
        gRootDiagnostic.publicationWindow = i;
        if (!gPendingDevice[i]->signedVolumeUuid (gPendingUuid[i])) return false;
        for (unsigned j = 0; j < i; ++j) if (!strcmp (gPendingUuid[i], gPendingUuid[j])) return false;
      }
      return true;
#else
      return false; // Root publication requires owner verification in every build.
#endif
    }
    bool schedule () {
      gRootDiagnostic.stage = "root publisher thread";
      gRootDiagnostic.publicationPhase = static_cast<unsigned> (UfsRootPhase::Schedule);
      gRootDiagnostic.publicationWindow = 0xffffffff;
      thread_t thread = nullptr;
      owner->retain ();
      if (kernel_thread_start (publishThread, nullptr, &thread) != KERN_SUCCESS) {
        owner->release ();
        return false;
      }
      thread_deallocate (thread);
      return true;
    }
    void discard (unsigned index) { discardPendingWindow (index); }
  } operations = { this, layout };
  UfsRootPublicationResult result = ufsPrepareRootWindows (operations, layout->windows);
  IOFree (layout, sizeof (RootLayout));
  if (result.phase != UfsRootPhase::Complete) {
    gPending = 0;
    gRootDiagnostic.result = result.phase == UfsRootPhase::Identity ? kIOReturnNotPrivileged :
      result.phase == UfsRootPhase::Schedule ? kIOReturnNoResources : kIOReturnError;
    IOLog ("NativeUfs: root preparation failed phase=%u window=%u; nothing published\n",
           static_cast<unsigned> (result.phase), result.index);
    IOService::stop (provider);
    rootDiagnosticFailure (result.phase == UfsRootPhase::Schedule ? "root publisher thread creation failed" :
                          result.phase == UfsRootPhase::Identity ? "signed window identities rejected" :
                          "root window preparation failed");
    return false;
  }
  return true;
}

#endif

void NativeUfs::stop (IOService *provider)
{
  fCmdDesc.reset ();
  fMap.reset ();
  IOService::stop (provider);
}
