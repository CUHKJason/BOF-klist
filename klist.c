#include <windows.h>
#include <ntsecapi.h>
#include "beacon.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(HANDLE LsaHandle,ULONG AuthenticationPackage,PVOID ProtocolSubmitBuffer,ULONG SubmitBufferLength,PVOID *ProtocolReturnBuffer,PULONG ReturnBufferLength,PNTSTATUS ProtocolStatus);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE LsaHandle);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE LsaHandle,PLSA_STRING PackageName,PULONG AuthenticationPackage);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer (PVOID Buffer);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$FileTimeToLocalFileTime (CONST FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$FileTimeToSystemTime (CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$GetDateFormatA (LCID Locale, DWORD dwFlags, CONST SYSTEMTIME *lpDate, LPCSTR lpFormat, LPSTR lpDateStr, int cchDate);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$GetTimeFormatA (LCID Locale, DWORD dwFlags, CONST SYSTEMTIME *lpTime, LPCSTR lpFormat, LPSTR lpTimeStr, int cchTime);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();


PCWCHAR kerberos_ticket_etype(LONG eType)
{
	PCWCHAR type;
    if (eType == KERB_ETYPE_DES_CBC_MD4)
    {
        type = L"DES-CBC-MD4";
    }
    else if (eType == KERB_ETYPE_DES_CBC_MD5)
    {
        type = L"DES-CBC-MD5";
    }
    else if (eType == KERB_ETYPE_DES_CBC_MD5_NT)
    {
        type = L"DES-CBC-MD5-NT";

    }
    else if (eType == KERB_ETYPE_RC4_HMAC_NT)
    {
        type = L"RC4-HMAC-NT";
    }
    else if (eType == KERB_ETYPE_RC4_HMAC_NT_EXP)
    {
        type = L"RC4-HMAC-NT-EXP";   
    }
    else
    {
        switch(eType)
        {
        // error
        // case KERB_ETYPE_DES_CBC_MD4:					type = L"DES-CBC-MD4      "; break;
        // case KERB_ETYPE_DES_CBC_MD5:					type = L"DES-CBC-MD5      "; break;
        // case KERB_ETYPE_DES_CBC_MD5_NT:					type = L"DES-CBC-MD5-NT   "; break;
        // case KERB_ETYPE_RC4_HMAC_NT:					type = L"RC4-HMAC-NT      "; break;
        // case KERB_ETYPE_RC4_HMAC_NT_EXP:				type = L"RC4-HMAC-NT-EXP  "; break;
        
        case KERB_ETYPE_NULL:							type = L"NULL             "; break;
        case KERB_ETYPE_DES_PLAIN:						type = L"DES-PLAIN        "; break;
        case KERB_ETYPE_DES_CBC_CRC:					type = L"DES-CBC-CRC      "; break;
        case KERB_ETYPE_RC4_PLAIN:						type = L"RC4-PLAIN        "; break;
        case KERB_ETYPE_RC4_PLAIN2:						type = L"RC4-PLAIN2       "; break;
        case KERB_ETYPE_RC4_PLAIN_EXP:					type = L"RC4-PLAIN-EXP    "; break;
        case KERB_ETYPE_RC4_LM:							type = L"RC4-LM           "; break;
        case KERB_ETYPE_RC4_MD4:						type = L"RC4-MD4          "; break;
        case KERB_ETYPE_RC4_SHA:						type = L"RC4-SHA          "; break;
        case KERB_ETYPE_RC4_PLAIN_OLD:					type = L"RC4-PLAIN-OLD    "; break;
        case KERB_ETYPE_RC4_PLAIN_OLD_EXP:				type = L"RC4-PLAIN-OLD-EXP"; break;
        case KERB_ETYPE_RC4_HMAC_OLD:					type = L"RC4-HMAC-OLD     "; break;
        case KERB_ETYPE_RC4_HMAC_OLD_EXP:				type = L"RC4-HMAC-OLD-EXP "; break;
        case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN:	type = L"AES128-CTS-HMAC-SHA1-96-Plain"; break;
        case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN:	type = L"AES256-CTS-HMAC-SHA1-96-Plain"; break;
        case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:		type = L"AES128-CTS-HMAC-SHA1-96      "; break;
        case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:		type = L"AES256-CTS-HMAC-SHA1-96      "; break;
        default:										type = L"Unknown           "; break;
        }
    }

	return type;
}


void kerberos_ticket_displayFlags(ULONG flags, formatp *buffer)
{
    char * TicketFlagsToStrings[] = 
    {
	"name_canonicalize", "?", "ok_as_delegate", "?",
	"hw_authent", "pre_authent", "initial", "renewable",
	"invalid", "postdated", "may_postdate", "proxy",
	"proxiable", "forwarded", "forwardable", "reserved",
    };
	DWORD i;

	for(i = 0; i < ARRAYSIZE(TicketFlagsToStrings); i++)
    {
        if((flags >> (i + 16)) & 1)
        {
            BeaconFormatPrintf(buffer, TicketFlagsToStrings[i]);
            BeaconFormatPrintf(buffer, "; ");
        }
    }
}

void string_displayLocalFileTime(IN PFILETIME pFileTime, PCWCHAR type, formatp *buffer)
{
	FILETIME ft;
    SYSTEMTIME st;
	char dbuffer[0xff];
    char dbuffer2[0xff];

	if(pFileTime)
    {
		if(KERNEL32$FileTimeToLocalFileTime(pFileTime, &ft))
        {
            if(KERNEL32$FileTimeToSystemTime(pFileTime, &st ))
            {
                if(KERNEL32$GetDateFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, dbuffer, sizeof(dbuffer)))
                {
                    if(KERNEL32$GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, dbuffer2, sizeof(dbuffer2)))
                    {
                        BeaconFormatPrintf(buffer, "\n   %ls: %s %s", type, dbuffer, dbuffer2);
                    }
                    else
                    {
                        BeaconPrintf(CALLBACK_ERROR, "Error: %ld", KERNEL32$GetLastError());
                    }  
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR, "Error: %ld", KERNEL32$GetLastError());
                }
            }
            else
            {
                BeaconPrintf(CALLBACK_ERROR, "Error: %ld", KERNEL32$GetLastError());
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "Error: %ld", KERNEL32$GetLastError());
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Error: %ld", KERNEL32$GetLastError());
    }
}

void go(char * args, int alen) {
    // init for LsaCallAuthenticationPackage
    STRING	kerberosPackageName = {8, 9, MICROSOFT_KERBEROS_NAME_A};
    DWORD	g_AuthenticationPackageId_Kerberos = 0;
    BOOL	g_isAuthPackageKerberos = FALSE;
    HANDLE	g_hLSA = NULL;

    NTSTATUS status = SECUR32$LsaConnectUntrusted(&g_hLSA);
	if(NT_SUCCESS(status))
	{
		status = SECUR32$LsaLookupAuthenticationPackage(g_hLSA, &kerberosPackageName, &g_AuthenticationPackageId_Kerberos);
		g_isAuthPackageKerberos = NT_SUCCESS(status);
	}
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Error: %ld", KERNEL32$GetLastError());
        return;
    }
        
    NTSTATUS packageStatus;
	KERB_QUERY_TKT_CACHE_REQUEST kerbCacheRequest = {KerbQueryTicketCacheExMessage, {0, 0}};
	PKERB_QUERY_TKT_CACHE_EX_RESPONSE pKerbCacheResponse;
	DWORD szData, i;

	if(g_hLSA && g_isAuthPackageKerberos)
    {
		status = SECUR32$LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, &kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID *) &pKerbCacheResponse, &szData, &packageStatus);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Error: %ld", KERNEL32$GetLastError());
        return;
    }

    if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(packageStatus))
		{
            BeaconPrintf(CALLBACK_OUTPUT, "Kerberos TGT of current session : ");
			for(i = 0; i < pKerbCacheResponse->CountOfTickets; i++)
			{
                // Ticket Output Format
                // Client:
                // Server:
                // KerbTicket Encryption Type:
                // Ticket Flags 0x -> xxx; xxx;
                // Start Time:
                // End Time:
                // Renew Time:

                formatp buffer;
                BeaconFormatAlloc(&buffer, 2048);
                BeaconFormatPrintf(&buffer, "\n[%08x]", i);
                BeaconFormatPrintf(&buffer, "\n   Client    : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ClientName, &pKerbCacheResponse->Tickets[i].ClientRealm);
                BeaconFormatPrintf(&buffer, "\n   Server    : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ServerName, &pKerbCacheResponse->Tickets[i].ServerRealm);
                BeaconFormatPrintf(&buffer, "\n   KerbTicket Encryption Type: %ls", kerberos_ticket_etype(pKerbCacheResponse->Tickets[i].EncryptionType));
                BeaconFormatPrintf(&buffer, "\n   Ticket Flags %08x -> ", pKerbCacheResponse->Tickets[i].TicketFlags);
				kerberos_ticket_displayFlags(pKerbCacheResponse->Tickets[i].TicketFlags, &buffer);
                string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].StartTime, L"Start Time", &buffer);
				string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].EndTime, L"End Time  ", &buffer);
				string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].RenewTime, L"Renew Time", &buffer);
                BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&buffer, NULL));
                BeaconFormatFree(&buffer);
			}
			SECUR32$LsaFreeReturnBuffer(pKerbCacheResponse);
            BeaconPrintf(CALLBACK_OUTPUT, "Done! \n");
		}
		else
        {
            BeaconPrintf(CALLBACK_ERROR, "LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message / Package : %08x\n", packageStatus);
            return;
        } 
	}
	else
    {
        BeaconPrintf(CALLBACK_ERROR, "LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message : %08x\n", status);
        return;
    }
}