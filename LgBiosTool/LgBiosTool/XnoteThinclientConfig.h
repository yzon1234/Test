#pragma once
#include "Meta.h"


#ifndef _XNOTE_THINCLIENT_CONFIG_H_
#define _XNOTE_THINCLIENT_CONFIG_H_

#define XNOTE_THINCLIENT_CONFIG_VARIABLE_GUID    "{B035916F-5327-40AB-8CFE-E3CE72D410F4}"
#define XNOTE_THINCLIENT_CONFIG_VARIABLE_NAME    "XnoteThinclientConfig"

//
// XNOTE_THINCLIENT_CONFIG variable template
//

#pragma pack(push, 1)
#if BIOS_SECURITY_ON
typedef struct {
	UINT8  ThinRtcS4WakeEnable;
	UINT8  ThinPostLogo;
	UINT8  ThinWlanEnable;
	UINT8  ThinBluetoothEnable;
	UINT8  ThinUsbPortEnable;
	UINT8  ThinMicroSdEnable;
	UINT8  ThinWebcamEnable;
	UINT8  ThinFingerPrintEnable;

	// BSK - define Thinclient USB ports to support External USB per-port disable
	// ThinUsbPortEnable[10] :
	// *CQ600(BOX)                  *24CQ(AIO)
	//    [0] : Front Upper            [0] : N/A (Webcam)
	//    [1] : Front Lower            [1] : Side ports (total 2 ports on USB hub)
	//    [2] : Rear Upper Left        [2] : Bottom Right Rear
	//    [3] : Rear Upper Right       [3] : Bottom Right Front
	//    [4] : Rear Lower Left        [4] : Bottom Left Rear
	//    [5] : Rear Lower Right       [5] : Bottom Left Front
	//    [6] : Rear Type-C            [6] : Type-C
	//  [7-9] : reserved             [7-9] : reserved
	UINT8  ThinUsbPerPort[10];
	UINT8  ThinUsbBootEnable;      //LGEMOD:[JHC220516B]
	UINT8  ThinLastPowerState;     //LGEMOD:[JHC220428A]

	UINT8  ThinLanEnable;          //LGEMOD:[JHC220428A]
	UINT8  ThinGprRtcReset;        //LGEMOD:[JHC220428A]
	UINT8  ThinWolEnable;
	UINT8  ThinPchHdAudio;

	UINT8  ThinNetworkStack;
	UINT8  ThinNumLock;
	UINT8  ThinUsbPowerShare;

	UINT8  ThinAcRecoveryBatteryEmpty;       // LGEMOD:[BSK220629A] - [ETC][Thin][PCSWBIOS-191] Add AC recovery menu in BIOS Setup for NT model
	UINT8  ThinAcRecoveryBatteryNotEmpty;

	UINT8  ThinHaveBattery;
	unsigned short ThinBootPriority[10]; // Max 20bytes
    UINT8  Reserved1;
	UINT8  ThinHash[32];
	UINT8  ThinSingKey[256];

	UINT8  Reserved2[45];  //JMK - for alignment   //384 bye         34
} XNOTE_THINCLIENT_CONFIG;
#else
typedef struct {
	UINT8  ThinRtcS4WakeEnable;
	UINT8  ThinPostLogo;
	UINT8  ThinWlanEnable;
	UINT8  ThinBluetoothEnable;
	UINT8  ThinUsbPortEnable;
	UINT8  ThinMicroSdEnable;
	UINT8  ThinWebcamEnable;
	UINT8  ThinFingerPrintEnable;

	// BSK - define Thinclient USB ports to support External USB per-port disable
	// ThinUsbPortEnable[10] :
	// *CQ600(BOX)                  *24CQ(AIO)
	//    [0] : Front Upper            [0] : N/A (Webcam)
	//    [1] : Front Lower            [1] : Side ports (total 2 ports on USB hub)
	//    [2] : Rear Upper Left        [2] : Bottom Right Rear
	//    [3] : Rear Upper Right       [3] : Bottom Right Front
	//    [4] : Rear Lower Left        [4] : Bottom Left Rear
	//    [5] : Rear Lower Right       [5] : Bottom Left Front
	//    [6] : Rear Type-C            [6] : Type-C
	//  [7-9] : reserved             [7-9] : reserved
	UINT8  ThinUsbPerPort[10];
	UINT8  ThinUsbBootEnable;      //LGEMOD:[JHC220516B]
	UINT8  ThinLastPowerState;     //LGEMOD:[JHC220428A]

	UINT8  ThinLanEnable;          //LGEMOD:[JHC220428A]
	UINT8  ThinGprRtcReset;        //LGEMOD:[JHC220428A]
	UINT8  ThinWolEnable;
	UINT8  ThinPchHdAudio;

	UINT8  ThinNetworkStack;
	UINT8  ThinNumLock;
	UINT8  ThinUsbPowerShare;

	UINT8  ThinAcRecoveryBatteryEmpty;       // LGEMOD:[BSK220629A] - [ETC][Thin][PCSWBIOS-191] Add AC recovery menu in BIOS Setup for NT model
	UINT8  ThinAcRecoveryBatteryNotEmpty;

	UINT8  ThinHaveBattery;
	unsigned short ThinBootPriority[10]; // Max 20bytes
	UINT8  Reserved2[30];
} XNOTE_THINCLIENT_CONFIG;
#endif

bool PrintThin(bool print);
void WriteThin(char *argv1,char *argv2);
void SaveThin();
void LoadThin();
void WriteSecurityKey(std::vector<unsigned char>& hash, std::vector<unsigned char>& signature);

#endif // _XNOTE_THINCLIENT_CONFIG_H_
