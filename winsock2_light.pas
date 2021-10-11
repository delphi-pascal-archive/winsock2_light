//---------------------Created by Atari-------------------------
//Облегченная версия библиотеки для работы с сетью Winsock2.
//
//В данной библиотеке собраны маски, структуры и функции
//для реализации сервера под windows с возможностью читать
//из сокета, записывать в сокет, принимать подключения от
//клиента и закрывать сокет.
//
//При реализации такого же сервера с полной библиотекой
//winsock2 размер сервера увеличивается в 2-2.5 раза.
//
//Дата создания: 22.06.07
//---------------------Created by Atari------------------------

unit winsock2_light;

interface

{$ALIGN OFF}
{$RANGECHECKS OFF}
{$WRITEABLECONST OFF}

const
  WINSOCK_VERSION = $0202;
  WINSOCK2_DLL = 'ws2_32.dll';

type
  HWND = type LongWord;
  DWORD = LongWord;
  LOWORD = Word;

const
  FD_READ_BIT      = 0;
  FD_WRITE_BIT     = 1;
  FD_ACCEPT_BIT    = 3;
  FD_CONNECT_BIT   = 4;
  FD_CLOSE_BIT     = 5;

  FD_READ       = (1 shl FD_READ_BIT);
  FD_WRITE      = (1 shl FD_WRITE_BIT);
  FD_ACCEPT     = (1 shl FD_ACCEPT_BIT);
  FD_CONNECT    = (1 shl FD_CONNECT_BIT);
  FD_CLOSE      = (1 shl FD_CLOSE_BIT);  


const
  AF_INET                    = 2;
  PF_INET                    = AF_INET;
  SOCK_STREAM                = 1;
  WSA_FLAG_OVERLAPPED        = $01;
  INADDR_ANY                 = $00000000;
  SOMAXCONN                  = $7fffffff;

const
  SD_RECEIVE = $00;
  SD_SEND    = $01;
  SD_BOTH    = $02;  

type
  TSocket = DWORD;
  WSAEVENT = THandle;
  PWSAEVENT = ^WSAEVENT;
  LPWSAEVENT = PWSAEVENT;

type
  u_char  = char;
  u_short = Word;
  u_int   = DWORD;
  u_long  = DWORD;

  SunB = packed record
    s_b1, s_b2, s_b3, s_b4: u_char;
  end;

  SunW = packed record
    s_w1, s_w2: u_short;
  end;

  TInAddr = packed record
    case integer of
      0: (S_un_b: SunB);
      1: (S_un_w: SunW);
      2: (S_addr: u_long);
  end;
  PInAddr = ^TInAddr;

  // Structure used by kernel to store most addresses.

  TSockAddrIn = packed record
    case Integer of
      0: (sin_family : u_short;
          sin_port   : u_short;
          sin_addr   : TInAddr;
          sin_zero   : array[0..7] of Char);
      1: (sa_family  : u_short;
          sa_data    : array[0..13] of Char)
  end;
  PSockAddrIn = ^TSockAddrIn;
  TSockAddr   = TSockAddrIn;
  PSockAddr   = ^TSockAddr;
  SOCKADDR    = TSockAddr;
  SOCKADDR_IN = TSockAddrIn;

const
  WSADESCRIPTION_LEN     =   256;
  WSASYS_STATUS_LEN      =   128;

type
  PWSAData = ^TWSAData;
  TWSAData = packed record
    wVersion       : Word;
    wHighVersion   : Word;
    szDescription  : Array[0..WSADESCRIPTION_LEN] of Char;
    szSystemStatus : Array[0..WSASYS_STATUS_LEN] of Char;
    iMaxSockets    : Word;
    iMaxUdpDg      : Word;
    lpVendorInfo   : PChar;
  end;

const
  WSAPROTOCOL_LEN    = 255;
  MAX_PROTOCOL_CHAIN = 7;

type
  TWSAProtocolChain = record
    ChainLen: Integer;  // the length of the chain,
    // length = 0 means layered protocol,
    // length = 1 means base protocol,
    // length > 1 means protocol chain
    ChainEntries: Array[0..MAX_PROTOCOL_CHAIN-1] of LongInt; // a list of dwCatalogEntryIds
  end;

type
  TWSAProtocol_InfoW = record
    dwServiceFlags1: LongInt;
    dwServiceFlags2: LongInt;
    dwServiceFlags3: LongInt;
    dwServiceFlags4: LongInt;
    dwProviderFlags: LongInt;
    ProviderId: TGUID;
    dwCatalogEntryId: LongInt;
    ProtocolChain: TWSAProtocolChain;
    iVersion: Integer;
    iAddressFamily: Integer;
    iMaxSockAddr: Integer;
    iMinSockAddr: Integer;
    iSocketType: Integer;
    iProtocol: Integer;
    iProtocolMaxOffset: Integer;
    iNetworkByteOrder: Integer;
    iSecurityScheme: Integer;
    dwMessageSize: LongInt;
    dwProviderReserved: LongInt;
    szProtocol: Array[0..WSAPROTOCOL_LEN+1-1] of WideChar;
  end;
PWSAProtocol_InfoW = ^TWSAProtocol_InfoW;
LPWSAProtocol_InfoW = PWSAProtocol_InfoW;
LPWSAProtocol_Info = PWSAProtocol_InfoW;

type
  GROUP = DWORD;

function accept( const s: TSocket; var addr: TSockAddr; var addrlen: Integer ): TSocket; stdcall;
function WSAStartup(wVersionRequired: word; var WSData: TWSAData): Integer; stdcall;
function WSASocket( af, iType, protocol : Integer; lpProtocolInfo : LPWSAProtocol_Info; g : GROUP; dwFlags : DWORD ): TSocket; stdcall;
function bind( const s: TSocket; const addr: PSockAddr; const namelen: Integer ): Integer; stdcall;
function listen(s: TSocket; backlog: Integer): Integer; stdcall;
function WSAAsyncSelect(s: TSocket; HWindow: HWND; wMsg: u_int; lEvent: Longint): Integer; stdcall;
function closesocket( const s: TSocket ): Integer; stdcall;
function recv(s: TSocket; var Buf; len, flags: Integer): Integer; stdcall;
function htons(hostshort: u_short): u_short; stdcall;
function shutdown(s: TSocket; how: Integer): Integer; stdcall;

function WSAGetSelectError(Param: Longint): Word;
function WSAGetSelectEvent(Param: Longint): Word;

implementation

function accept;  external WINSOCK2_DLL name 'accept';
function WSAStartup;  external WINSOCK2_DLL name 'WSAStartup';
function WSASocket; external WINSOCK2_DLL name 'WSASocketA';
function bind;  external WINSOCK2_DLL name 'bind';
function listen;  external WINSOCK2_DLL name 'listen';
function WSAAsyncSelect;  external WINSOCK2_DLL name 'WSAAsyncSelect';
function closesocket; external WINSOCK2_DLL name 'closesocket';
function recv;  external WINSOCK2_DLL name 'recv';
function htons; external WINSOCK2_DLL name 'htons';
function shutdown;  external WINSOCK2_DLL name 'shutdown';

function HiWord(L: DWORD): Word;
begin
  Result := L shr 16;
end;

function WSAGetSelectError;
begin
  WSAGetSelectError:= HIWORD(Param);
end;

function WSAGetSelectEvent;
begin
  WSAGetSelectEvent:= LOWORD(Param);
end;

end.
