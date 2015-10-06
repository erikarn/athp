/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _ATHP_PCI_H_
#define _ATHP_PCI_H_

/*
 * maximum number of bytes that can be handled atomically by DiagRead/DiagWrite
 */
#define DIAG_TRANSFER_LIMIT 2048

/*
 * maximum number of bytes that can be
 * handled atomically by DiagRead/DiagWrite
 */
#define DIAG_TRANSFER_LIMIT 2048

struct bmi_xfer {
	bool tx_done;
	bool rx_done;
	bool wait_for_resp;
	u32 resp_len;
};

/*
 * PCI-specific Target state
 *
 * NOTE: Structure is shared between Host software and Target firmware!
 *
 * Much of this may be of interest to the Host so
 * HOST_INTEREST->hi_interconnect_state points here
 * (and all members are 32-bit quantities in order to
 * facilitate Host access). In particular, Host software is
 * required to initialize pipe_cfg_addr and svc_to_pipe_map.
 */
struct pcie_state {
	/* Pipe configuration Target address */
	/* NB: ce_pipe_config[CE_COUNT] */
	u32 pipe_cfg_addr;

	/* Service to pipe map Target address */
	/* NB: service_to_pipe[PIPE_TO_CE_MAP_CN] */
	u32 svc_to_pipe_map;

	/* number of MSI interrupts requested */
	u32 msi_requested;

	/* number of MSI interrupts granted */
	u32 msi_granted;

	/* Message Signalled Interrupt address */
	u32 msi_addr;

	/* Base data */
	u32 msi_data;

	/*
	 * Data for firmware interrupt;
	 * MSI data for other interrupts are
	 * in various SoC registers
	 */
	u32 msi_fw_intr_data;

	/* PCIE_PWR_METHOD_* */
	u32 power_mgmt_method;

	/* PCIE_CONFIG_FLAG_* */
	u32 config_flags;
};

/* PCIE_CONFIG_FLAG definitions */
#define PCIE_CONFIG_FLAG_ENABLE_L1  0x0000001

/* Host software's Copy Engine configuration. */
#define CE_ATTR_FLAGS 0

/*
 * Configuration information for a Copy Engine pipe.
 * Passed from Host to Target during startup (one per CE).
 *
 * NOTE: Structure is shared between Host software and Target firmware!
 */
struct ce_pipe_config {
	__le32 pipenum;
	__le32 pipedir;
	__le32 nentries;
	__le32 nbytes_max;
	__le32 flags;
	__le32 reserved;
};

/*
 * Directions for interconnect pipe configuration.
 * These definitions may be used during configuration and are shared
 * between Host and Target.
 *
 * Pipe Directions are relative to the Host, so PIPEDIR_IN means
 * "coming IN over air through Target to Host" as with a WiFi Rx operation.
 * Conversely, PIPEDIR_OUT means "going OUT from Host through Target over air"
 * as with a WiFi Tx operation. This is somewhat awkward for the "middle-man"
 * Target since things that are "PIPEDIR_OUT" are coming IN to the Target
 * over the interconnect.
 */
#define PIPEDIR_NONE    0
#define PIPEDIR_IN      1  /* Target-->Host, WiFi Rx direction */
#define PIPEDIR_OUT     2  /* Host->Target, WiFi Tx direction */
#define PIPEDIR_INOUT   3  /* bidirectional */

/* Establish a mapping between a service/direction and a pipe. */
struct service_to_pipe {
	__le32 service_id;
	__le32 pipedir;
	__le32 pipenum;
};

struct athp_pci_supp_chip {
	u32 dev_id;
	u32 rev_id;
};

#define ATH10K_PCI_RX_POST_RETRY_MS 50
#define ATH_PCI_RESET_WAIT_MAX 10 /* ms */
#define PCIE_WAKE_TIMEOUT 10000	/* 10ms */

#define BAR_NUM 0

#define CDC_WAR_MAGIC_STR   0xceef0000
#define CDC_WAR_DATA_CE     4

/* Wait up to this many Ms for a Diagnostic Access CE operation to complete */
#define DIAG_ACCESS_CE_TIMEOUT_MS 10

/* QCA6174 is known to have Tx/Rx issues when SOC_WAKE register is poked too
 * frequently. To avoid this put SoC to sleep after a very conservative grace
 * period. Adjust with great care.
 */
#define ATH10K_PCI_SLEEP_GRACE_PERIOD_MSEC 60

#endif /* _PCI_H_ */
