// SPDX-License-Identifier: BSD-2-Clause-Patent
// SM8750 GCC registers used by UFS, transcribed as facts from the public
// Linux gcc-sm8750.c clock driver. No write is performed by NativeUfs yet.
// erhai copy of the upstream (sheng, SM8550) header: the GDSCs and the AXI
// branch sit at the same offsets, the other branches moved by 4..12 bytes.
#ifndef NATIVE_UFS_GCC_UFS_H
#define NATIVE_UFS_GCC_UFS_H

// Physical windows from the erhai live DT (gcc, ufshc@1d84000 reg 0x1d84000 0x3000).
#define GCC_BASE                      0x00100000ULL
#define UFS_HC_BASE                   0x01d84000ULL
#define UFS_HC_SIZE                   0x3000ULL

#define GCC_UFS_PHY_GDSCR             0x77004
#define GCC_UFS_MEM_PHY_GDSCR         0x9e000

#define GCC_UFS_PHY_AXI_ENABLE        0x77018
#define GCC_UFS_PHY_AHB_ENABLE        0x77028
#define GCC_UFS_PHY_TX_SYMBOL0_ENABLE 0x7702c
#define GCC_UFS_PHY_RX_SYMBOL0_ENABLE 0x77030
#define GCC_UFS_PHY_UNIPRO_CORE_ENABLE 0x7706c
#define GCC_UFS_PHY_ICE_CORE_ENABLE   0x7707c
#define GCC_UFS_PHY_PHY_AUX_ENABLE    0x770bc
#define GCC_UFS_PHY_RX_SYMBOL1_ENABLE 0x770d8
// bus_aggr_clk: gcc_aggre_ufs_phy_axi_clk, halt/enable 0x770f0 in gcc-sm8750.c
#define GCC_AGGRE_UFS_PHY_AXI_ENABLE  0x770f0

#define GCC_UFS_BRANCH_ENABLE_BIT     0x1U

// The reset and RPMh/TCSR/QMP-PHY programming are not represented here: their
// semantics are not qualified and NativeUfs must not write them speculatively.
#endif
