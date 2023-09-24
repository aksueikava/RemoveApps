# Определение оболочки.
if ( $host.Name -eq 'ConsoleHost' ) { [bool] $isConsole = $true }

# Если консоль, то установить параметры цвета и кодировки для текущей консоли.
if ( $isConsole )
{
    $host.UI.RawUI.BackgroundColor = "Black"
    $host.PrivateData.WarningForegroundColor = "Yellow"
    $host.PrivateData.VerboseForegroundColor = "Blue"

    $BufferHeight = $host.UI.RawUI.BufferSize.Height
    if ( $BufferHeight -lt 9000 )
    {
        $BufferHeightNew = New-Object System.Management.Automation.Host.Size($host.UI.RawUI.BufferSize.Width,9000)
        $host.UI.RawUI.BufferSize = $BufferHeightNew
    }

    [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding('utf-8')
}


# Функция для установки паузы в зависимости от оболочки: ISE или Консоль.
# Но только если запуск скрипта без аргументов автозапуска выполнения быстрых настроек.
# То есть не будет пауз при вызове функции Get-Pause во всех функциях, во время автоматического выполнения быстрых настроек.
Function Get-Pause {

    if ( $isConsole )
    {
        Write-Host "`n Для продолжения нажмите любую клавишу ..."

        # Сброс нажатых клавиш клавиатуры в процессе выполнения,
        # чтобы консоль не обрабатывала эти действия после вызова паузы.
        $Host.UI.RawUI.FlushInputBuffer()

        $host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown") > $null
    }
    else { Read-Host -Prompt "`n Для продолжения нажмите 'Enter'" }
}


# Остановка выполнения, если скрипт запущен из 32 битной программы в 64 битной системе.
if ( [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess ) {
    Write-Warning "`n  Скрипт запущен из 32 битной программы `n  Повторите запуск из 64 битной. `n  Выход. `n "
    Get-Pause ; Exit
}

# Результат состояния наличия прав Администратора у текущей оболочки.
$AdminRight = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
               [Security.Principal.WindowsBuiltInRole]::Administrator)

# Получение типа доступа и названия, для отображения его в заголовке окна.
if ( $AdminRight )
{
    if ( [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem )
    {
        if ( [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value.Where({ $_ -like 'S-1-5-80-*' },'First',1) )
        {
            [string] $CurrentRight = 'TrustedInstaller'
        }
        else
        {
            [string] $CurrentRight = 'System'
        }
    }
    else
    {
        [string] $AdminDefaultLocalUserName = (Get-LocalUser).Where({ $_.SID.Value -match '^S-1-5-21-[\d-]+-500$'}).Name
        [string] $CurrentRight = $AdminDefaultLocalUserName
    }
}


# Изменение заголовка окна консоли, в зависимости от прав доступа.
if ( -not $AdminRight ) { $host.UI.RawUI.WindowTitle = 'RemoveApps' }
else { $host.UI.RawUI.WindowTitle = "$CurrentRight`: RemoveApps" }


if (( $CurrentRight -match 'TrustedInstaller|System' ) -or ( -not $AdminRight ))
{
     Write-Warning "`n  Скрипт должен быть запущен с правами Администратора`n  Текущие права: '$CurrentRight'`n`n  Выход `n "
     Get-Pause ; Exit
}



[int] $BuildOS = [System.Environment]::OSVersion.Version.Build

if ( $BuildOS -lt 17763 )
{
    Write-Warning "`n  Скрипт рассчитан на версию системы от 1809 (17763), Ваша версия: '$BuildOS'`n`n  Выход `n "
    Get-Pause ; Exit 
}

if ( [System.Environment]::Is64BitOperatingSystem ) { $ArchOS = 'x64' } else { $ArchOS = 'x86' }




# Функция определения текущего расположения корневой папки в зависимости от оболочки: ISE или Консоль.
Function Get-CurrentRoot { if ( $isConsole ) { $CurrentRoot = $PSScriptRoot }
    else { $CurrentRoot = [System.IO.Path]::GetDirectoryName($psISE.CurrentFile.Fullpath) }
    [System.IO.Path]::GetDirectoryName($CurrentRoot)
}

# Текущее расположение скрипта, постоянная переменная.
Set-Variable -Name CurrentRoot -Value (Get-CurrentRoot) -Option Constant -Force




######################################################################################

$ListApps = "$CurrentRoot\ListApps.txt"

$ExportListApps = "$CurrentRoot\ExportListApps_$((Get-Date).ToString('yyyyMMdd-HHmmss')).txt"

# Установить это значение для IsInbox:
[int] $SetIsInbox = 0

#######################################################################################



[string[]] $PackNames = $null
[string[]] $DoNotRemovePackNames = $null

# Если файл с пресетами существует.
if ( [System.IO.File]::Exists($ListApps) )
{
    # Получение пресетов в переменную.
    try
    {
        $Content = (Get-Content -LiteralPath \\?\$ListApps -Encoding UTF8 -ErrorAction SilentlyContinue).Where({
            if     ( $_ -match "(?<Name>^[a-z\d-\._]+)"    ) { $PackNames     += $matches.Name }
            elseif ( $_ -match "^\*+(?<Name>[a-z\d-\._]+)" ) { $DoNotRemovePackNames += $matches.Name }
        })
        
        $PackNames = $PackNames | Select-Object -Unique

        [string[]] $AllPackNames = $PackNames

        # Удаление исключенных apps из списка приложений для удаления, если такие есть.
        if ( $DoNotRemovePackNames )
        {
            $DoNotRemovePackNames = $DoNotRemovePackNames | Select-Object -Unique
            $PackNames = $PackNames -notmatch ( $DoNotRemovePackNames -join '|' )
        }
    }
    catch {}
}
else
{
    Write-Warning "`n  Нет файла списка приложений: '$ListApps'`n`n  Выход `n "
    Get-Pause ; Exit 
}




Set-Variable -Name SQLiteDll -Value ([string] "$CurrentRoot\Files\$ArchOS\System.Data.SQLite.dll") -Option Constant -Force

# Проверки существования важных файлов.
if ( -not [System.IO.File]::Exists($SQLiteDll) )
{ Write-Warning "`n   Не найден SQLite.dll: '$SQLiteDll'`n " ; Get-Pause ; Exit } # Выход.



do
{
    Clear-Host
    Start-Sleep -Milliseconds 100

    Write-Host
    Write-Host " =====================================================================================" -ForegroundColor DarkGray
    Write-Host "        Удаление модерн приложений, включая встроенные системные " -ForegroundColor White -NoNewline
    Write-Host "| Версия 0.0.4" -ForegroundColor DarkGray
    Write-Host " =====================================================================================" -ForegroundColor DarkGray

    Write-Host "`n        Указанные приложения в " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($ListApps | Split-Path -leaf):`n" -ForegroundColor White

    [int] $N = 0

    if ( $PackNames.Count )
    {
        $AllPackNames | ForEach-Object {

            if ( $DoNotRemovePackNames -and $_ -match ( $DoNotRemovePackNames -join '|' ))
            {
                Write-Host "              $_ | Пропустится, совпадение с исключениями"  -ForegroundColor Red
            }
            else
            {
                $N++
                if ( 10 -gt $N ) { $Space = ' ' } else { $Space = '' }

                Write-Host "          $Space$N. " -NoNewline
                
                Write-Host "$_"  -ForegroundColor Blue
            }
        }
    }
    else
    {
        Write-Host "`n  Не указаны приложения для удаления!" -ForegroundColor Yellow
        Write-Host "`n   Выход" -ForegroundColor Yellow ; Start-Sleep -Milliseconds 3000 ; Exit
    }
    


    Write-Host "`n        Исключённые приложения из удаления в " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($ListApps | Split-Path -leaf):" -ForegroundColor White

    [int] $N = 0

    if ( $DoNotRemovePackNames.Count )
    {
        Write-Host

        $DoNotRemovePackNames | ForEach-Object {
            $N++
            if ( 10 -gt $N ) { $Space = ' ' } else { $Space = '' }
            Write-Host "          $Space$N. " -ForegroundColor DarkGray -NoNewline
            Write-Host "$_"  -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "          Не указаны исключения из удаления" -ForegroundColor DarkGray
    }
    

    Write-Host "`n        Выберите нужный вариант:" -ForegroundColor DarkGray

    Write-Host "`n    [1] " -ForegroundColor Cyan -NoNewline
    Write-Host "= " -ForegroundColor DarkGray -NoNewline
    Write-Host "Экспортировать список установленных приложений " -ForegroundColor Gray -NoNewline
    Write-Host "| " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($ExportListApps | Split-Path -leaf) " -ForegroundColor Green

    Write-Host "`n  [777] " -ForegroundColor Magenta -NoNewline
    Write-Host "= " -ForegroundColor DarkGray -NoNewline
    Write-Host "Удалить " -ForegroundColor Magenta -NoNewline
    Write-Host "указанные приложения" -ForegroundColor Gray

    Write-Host "`n  [Без ввода] " -ForegroundColor Cyan -NoNewline
    Write-Host "= Выйти`n" -ForegroundColor DarkGray

    # Получаем выбор от пользователя.
    try { [string] $Choice = Read-Host -Prompt '   Ваш выбор' } catch {}

    # Если выбор пустая строка, выход.
    if ( '' -eq $Choice ) { Write-Host "`n   Выход" -ForegroundColor Yellow ; Start-Sleep -Milliseconds 1000 ; Exit }

    if ( 1,777 -notcontains $Choice )
    {
        Write-Host "`n   Неправильный выбор!`n" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 1000
    }
}
until ( 1,777 -contains $Choice )


  # Далее нужные функции и выполнение всех действий ...

  # Get-Pause
  # Exit

<#
.SYNOPSIS
 Олицетворение (Impersonate) себя за TrustedInstaller или SYSTEM (подключение токена от этих процессов).
 С их доступом и + дополнительно включенными у полученного токена всеми доступными для него привилегиями.

.DESCRIPTION
 Олицетворение (Impersonate) - "Представиться другим" подменой токена.
 Это легальная возможность через WIN API.
 Берется токен у процесса с необходимым доступом, и подменяется вместо токена у текущей среды.
 Текущая среда получает доступ и привилегии того процесса, оставаясь при этом в своем окружении!
 То есть раздел реестра HKCU остается доступным.

 Подмена токена (Impersonate) у текущей среды осуществляется
 без перезапуска текущего процесса, то есть на лету.
 С возможностью сброса Олицетворения.

 У Токена дополнительно включаются все возможные, но не задействованные привилегии.

 При Олицетворении в системе доступны не все действия, особенно при TrustedInstaller!
 Так как эти токены специально урезанные для разграничения доступов безопасности.
 TrustedInstaller - это права System, но со своими привилегиями и возможностями.
 Для доступа к файловой системе или реестру при любом Олицетворении работает корректно.
 При Олицетворении за TrustedInstaller нет доступа на применение SDDL и некоторые другие.

 Также закрыт доступ в некоторых случаях на изменение к WMI, например не дает доступ к CIM ресурсам через SCHTASKS,
 но через командлеты типа Enable-ScheduledTask дает.
 Настройку планировщика задач Windows можно выполнить через запуск отдельного процесса,
 с нужными правами, или получать доступ на файлы задач и/или реестр.
 Использование DISM под Impersonate за TI также не получится, или whoami.exe и др.

 Если параметр запуска службы TrustedInstaller будет измененный,
 то он будет восстановлен "По умолчанию",
 чтобы была возможность запустить TrustedInstaller для получения его токена.

.PARAMETER Token
 Чьим токеном осуществить олицетворение.
 TI  = токен с правами TrustedInstaller. Берется у службы TrustedInstaller.
 SYS = токен с правами SYSTEM (S-1-5-18). Берется у процесса winlogon.exe.
 Токены берутся только один раз в текущей сессии, далее используются все время сохраненные в переменных.

.PARAMETER Reset
 Сброс Олицетворения, сохраняя возможность повторного олицетворения,
 мгновенно, без получения.

.EXAMPLE
    Token-Impersonate -Token SYS

    Описание
    --------
    Олицетворение текущей среды за System.
    Без вывода подробностей.


.EXAMPLE
    Token-Impersonate -Token TI -Verbose

    Описание
    --------
    Олицетворение текущей среды за TrustedInstaller.
    С выводом подробных действий.

.EXAMPLE
    Token-Impersonate -Reset

    Описание
    --------
    Сброс Олицетворения.
    Без вывода подробностей.


.NOTES
    Made with ❤️ by Watashi o yūwaku suru

#>
Function Token-Impersonate {

    [CmdletBinding( SupportsShouldProcess = $false )]
    [OutputType([bool])]
    Param (
        [parameter( Mandatory = $false, ParameterSetName = 'Token', Position = 0 )]
        [ValidateSet( 'TI', 'SYS' )]
        [string] $Token = 'SYS'
       ,
        [parameter( Mandatory = $true,  ParameterSetName = 'ResetToken' )]
        [switch] $Reset
    )

    Begin
    {
        # Перехват ошибок в блоке Begin, для выхода из функции,
        # без отображения ошибки тут, и передача ее в глобальный trap для отображения и записи в лог.
        trap { Write-Warning "$NameThisFunction`: Ошибка в Begin: `n   $($_.CategoryInfo.Category): $($_.Exception.Message)" ; break }

        # Получение имени этой функции.
        $NameThisFunction = $MyInvocation.MyCommand.Name

        [bool] $Exit = $false

        [string] $GetTokenAPI = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace WinAPI
{
    public static class WinBase
    {
        [StructLayout( LayoutKind.Sequential )]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout( LayoutKind.Sequential )]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout( LayoutKind.Sequential )]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
    }

    public static class WinNT
    {
        public const Int32 ANYSIZE_ARRAY = 1;
        public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        public const string SE_AUDIT_NAME = "SeAuditPrivilege";
        public const string SE_BACKUP_NAME = "SeBackupPrivilege";
        public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
        public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
        public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
        public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
        public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
        public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
        public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
        public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
        public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
        public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
        public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
        public const string SE_RELABEL_NAME = "SeRelabelPrivilege";
        public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
        public const string SE_RESTORE_NAME = "SeRestorePrivilege";
        public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
        public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
        public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
        public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
        public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
        public const string SE_TCB_NAME = "SeTcbPrivilege";
        public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
        public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
        public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
        public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        [StructLayout( LayoutKind.Sequential )]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout( LayoutKind.Sequential, Pack = 4 )]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=WinNT.ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES [] Privileges;
        }
    }

    public static class Advapi32
    {
        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (
            STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
            TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
            TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
        );

        [Flags]
        public enum CreateProcessFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        [DllImport( "advapi32.dll", SetLastError = true )]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle
        );

        [DllImport( "advapi32.dll", CharSet = CharSet.Auto, SetLastError = true )]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref WinBase.SECURITY_ATTRIBUTES lpTokenAttributes,
            WinNT.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            WinNT.TOKEN_TYPE TokenType,
            out IntPtr phNewToken
        );

        [DllImport( "advapi32.dll", CharSet = CharSet.Auto, SetLastError = true )]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out WinNT.LUID lpLuid
        );

        [DllImport( "advapi32.dll", SetLastError = true )]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
            ref WinNT.TOKEN_PRIVILEGES NewState,
            UInt32 Zero,
            IntPtr Null1,
            IntPtr Null2
        );

        [DllImport( "advapi32.dll", SetLastError = true )]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken
        );

        [DllImport( "advapi32.dll", SetLastError = true )]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref WinBase.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref WinBase.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref WinBase.STARTUPINFO lpStartupInfo,
            out WinBase.PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport( "advapi32.dll", CharSet = CharSet.Auto, SetLastError = true )]
        public static extern bool RevertToSelf();
    }

    public static class Kernel32
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport( "kernel32.dll", SetLastError = true )]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId
        );
    }

    public static class UserEnv
    {
        [DllImport( "userenv.dll", SetLastError = true )]
        public static extern bool CreateEnvironmentBlock(
            ref IntPtr lpEnvironment,
            IntPtr hToken,
            bool bInherit
        );
    }
}
'@

        if ( -not ( 'WinAPI.WinBase' -as [type] )) { Add-Type -TypeDefinition $GetTokenAPI -ErrorAction Stop }

        # Если не получена еще, то получаем в глобальную переменную идентификацию (личность) у текущей среды (оболочки),
        # для возможности сброса любых Олицетворений (подключенных токенов).
        if ( 'System.Security.Principal.WindowsImpersonationContext' -ne "$Global:CurrentShell" )
        {
            Write-Verbose "Получаем идентификацию текущей оболочки без Олицетворения, для возможности сброса Олицетворения"

            # Сбрасываем олицетворение, чтобы получить доступ к текущей оболочке без олицетворения, оно может уже быть выполнено.
            # Но так как этот сброс полный, то нужно после этого получить идентификацию текущей оболочки обратно.
            # Иначе после этого не будет доступа для некоторых действий с WMI,
            # например для использования командлета Test-Connection, если он был выполнен хотябы раз под чужим олицетворением.
            [WinAPI.Advapi32]::RevertToSelf() > $null

            if ( [System.Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel -ne 'Impersonation' )
            {
                # Получаем идентификацию текущей среды, включая олицетворение себя на себя.
                [PSObject] $Global:CurrentShell = [System.Security.Principal.WindowsIdentity]::GetCurrent().Impersonate()

                # Сбрасываем Олицетворение себя на себя после получения идентификации, тем самым восстанавливаем идентификацию после RevertToSelf().
                try { $Global:CurrentShell.Undo()    } catch {}
                try { $Global:CurrentShell.Dispose() } catch {}
            }
            else { Write-Warning "$NameThisFunction`: Ошибка, текущая оболочка уже с Олицетворением!" ; [bool] $Exit = $true ; Return }
        }

        # Если указан Cброс Олицетворения.
        if ( $Reset )
        {
            # Если олцетворение уже выполнено.
            if ( [System.Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel -eq 'Impersonation' )
            {
                Write-Verbose "Сбрасываем Олицетворение"

                # На всякий случай, если с первого раза не бедет сброшено Олицетворение, будут дополнительные попытки сброса, но не больше 10 раз.
                [int] $DisposeCount = 0
                while ( [System.Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel -eq 'Impersonation' )
                {
                    try { $Global:CurrentShell.Undo()    } catch {}
                    try { $Global:CurrentShell.Dispose() } catch {}

                    if ( [System.Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel -eq 'Impersonation' )
                    {
                        Start-Sleep -Milliseconds 100 ; $DisposeCount++
                        if ( $DisposeCount -eq 10 ) { Write-Warning "Ошибка, Олицетворение не сброшено!" ; [bool] $Exit = $true ; Return }
                    }
                    else { Write-Verbose "Сброшено" }
                }
            }
            else { Write-Verbose "Сброс Олицетворения не требуется." }

            [bool] $Exit = $true ; Return  # Выходим из функции.
        }

        # Внутренняя функция получения дубликата токена.
        Function Duplicate-ProcessToken {

            [CmdletBinding( SupportsShouldProcess = $false )]
            [OutputType([IntPtr],[bool])]
            Param (
                [parameter( Mandatory = $true,  Position = 0 )]
                [int] $ProcessID
               ,
                [parameter( Mandatory = $false, Position = 1 )]
                [ValidateSet( 'Primary', 'Impersonation' )]
                [string] $TokenType = 'Impersonation'
            )

            Write-Verbose "Получение токена у ID процесса: '$ProcessID'"

            [IntPtr] $ProcessHandle = [WinAPI.Kernel32]::OpenProcess( [WinAPI.Kernel32+ProcessAccessFlags]::All, $true, $ProcessID )
            [uint32] $DesiredAccess = [WinAPI.Advapi32]::TOKEN_QUERY -bor [WinAPI.Advapi32]::TOKEN_DUPLICATE -bor [WinAPI.Advapi32]::TOKEN_ASSIGN_PRIMARY
            [IntPtr] $ProcessToken  = New-Object -TypeName System.IntPtr
            [WinAPI.Advapi32]::OpenProcessToken($ProcessHandle, $DesiredAccess, [Ref] $ProcessToken) > $null

            Write-Verbose "Получение дубликата токена с полным доcтупом, с Типом: '$TokenType'"

            [IntPtr] $NewProcessToken = New-Object -TypeName System.IntPtr
            [uint32] $DesiredAccess   = [WinAPI.Advapi32]::TOKEN_ALL_ACCESS

            [PSObject] $SecurityAttributes = New-Object -TypeName WinAPI.WinBase+SECURITY_ATTRIBUTES
                       $SecurityAttributes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttributes)
            [PSObject] $ImpersonationLevel = [WinAPI.WinNT+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation

            if ( $TokenType -eq 'Impersonation' )
            {      [PSObject] $isTokenType = [WinAPI.WinNT+TOKEN_TYPE]::TokenImpersonation }
            else { [PSObject] $isTokenType = [WinAPI.WinNT+TOKEN_TYPE]::TokenPrimary }

            [WinAPI.Advapi32]::DuplicateTokenEx( $ProcessToken, $DesiredAccess, [Ref] $SecurityAttributes, $ImpersonationLevel, $isTokenType, [Ref] $NewProcessToken ) > $null

            Write-Verbose "Включение всех привилегий у токена (которые отключены у TI и System)"

            [string[]] $Privilages = 'SeAssignPrimaryTokenPrivilege','SeIncreaseQuotaPrivilege','SeLoadDriverPrivilege',
                                     'SeTakeOwnershipPrivilege','SeBackupPrivilege', 'SeRestorePrivilege',
                                     'SeSecurityPrivilege','SeShutdownPrivilege','SeSystemEnvironmentPrivilege','SeManageVolumePrivilege',
                                     'SeTrustedCredmanAccessPrivilege','SeUndockPrivilege','SeSystemTimePrivilege','SeTrustedCredmanAccessPrivilege'

            [PSObject] $NewTokenPrivlege = New-Object -TypeName WinAPI.WinNT+TOKEN_PRIVILEGES
                       $NewTokenPrivlege.PrivilegeCount = 1

            [PSObject] $TokenLUIDAndAttributes = New-Object -TypeName WinAPI.WinNT+LUID_AND_ATTRIBUTES
               [int32] $TokenLUIDAndAttributes.Attributes = [WinAPI.Advapi32]::SE_PRIVILEGE_ENABLED
            [PSObject] $TokenLUID = New-Object -TypeName WinAPI.WinNT+LUID

            foreach ( $Privilage in $Privilages.Where({$_}) )
            {
                [WinAPI.Advapi32]::LookupPrivilegeValue('', $Privilage, [Ref] $TokenLUID ) > $null
                $TokenLUIDAndAttributes.Luid = $TokenLUID
                $NewTokenPrivlege.Privileges = $TokenLUIDAndAttributes
                [WinAPI.Advapi32]::AdjustTokenPrivileges( $NewProcessToken, $false, [Ref] $NewTokenPrivlege, 0, [System.IntPtr]::Zero, [System.IntPtr]::Zero ) > $null
            }

            # Результат [IntPtr] Дубликат токена со всеми привилегиями:
            $NewProcessToken
        }

        # Если не получена еще идентификация от системы, то получаем токен системы у процесса winlogon.exe,
        # и глобальную переменную, с идентификацией на его основе.
        # Токен TrustedInstaller можно получить только с Олицетворением за систему, так как только у системы есть необходимые для этого привилегии.
        if ( 'Impersonation' -ne $Global:Identity_SYS.ImpersonationLevel )
        {
            Write-Verbose "Получаем токен от SYSTEM (winlogon)"

            try
            {
                [IntPtr] $Token_SYS = Duplicate-ProcessToken -ProcessID ((Get-Process -Name winlogon).Id | Select-Object -First 1) -TokenType 'Impersonation'
            }
            catch { Write-Warning "$NameThisFunction`: Ошибка получения токена от SYSTEM (winlogon)!" ; [bool] $Exit = $true ; Return }

            if ( $Token_SYS )
            {
                Write-Verbose "Получаем идентификацию `$Global:Identity_SYS с токеном от SYSTEM (winlogon)"

                try
                {
                    [PSObject] $Global:Identity_SYS = [System.Security.Principal.WindowsIdentity]::new($Token_SYS)
                }
                catch { Write-Warning "$NameThisFunction`: Ошибка, при создании идентификации с токеном от SYSTEM (winlogon)!" ; [bool] $Exit = $true ; Return }
            }
            else { Write-Warning "$NameThisFunction`: Ошибка, токен от SYSTEM (winlogon) не получен!" ; [bool] $Exit = $true ; Return }
        }

        # Если указано получить токен от TrustedInstaller.
        if ( $Token -eq 'TI' )
        {
            # Если не получена еще идентификация от TrustedInstaller.
            if ( $Global:Identity_TI.ImpersonationLevel -ne 'Impersonation' )
            {
                Write-Verbose "Олицетворяем себя за SYSTEM, для получения токена от TrustedInstaller"

                # Олицетворяем себя за System, со всеми привилегиями.
                try { $Global:Identity_SYS.Impersonate() > $null }
                catch
                {
                    Write-Warning "$NameThisFunction`: Ошибка Олицетворения себя за SYSTEM!" ; [bool] $Exit = $true ; Return
                }

                [string] $SubKey = 'SYSTEM\CurrentControlSet\Services\TrustedInstaller'

                [int] $StartType = 0

                # Получаем параметр типа запуска у службы TrustedInstaller (Установщик модулей Windows).
                try { $StartType = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey,'ReadSubTree','QueryValues').GetValue('Start',$null) } catch {}

                # Если параметр запуска не является 2 (Авто) или 3 (Вручную).
                if (( 3 -ne $StartType ) -and ( 2 -ne $StartType ))
                {
                    Write-Verbose "  Устанавливаем тип запуска у службы TrustedInstaller 'Вручную' (По умолчанию)"

                    # Восстанавливаем доступ по умолчанию.
                    $OpenSubKeyTI = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey,'ReadWriteSubTree', 'TakeOwnership')
                    $AclTI = [System.Security.AccessControl.RegistrySecurity]::new()
                    $AclTI.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
                    $AclTI.SetGroup([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
                    $OpenSubKeyTI.SetAccessControl($AclTI)
                    $AclTI.SetSecurityDescriptorSddlForm('O:BAG:BAD:PAI(A;;KA;;;SY)(A;CIIO;GA;;;SY)(A;;KR;;;BA)(A;CIIO;GXGR;;;BA)(A;;KR;;;BU)(A;CIIO;GXGR;;;BU)')
                    $OpenSubKeyTI.SetAccessControl($AclTI)

                    # Задаем параметр запуска по умолчанию.
                    [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey,'ReadWriteSubTree').SetValue('Start',3,'Dword')
                }

                try
                {
                    Write-Verbose "Запускаем службу TrustedInstaller"

                    Start-Service -Name TrustedInstaller -ErrorAction SilentlyContinue

                    [int] $pidTI = ((Get-Process -Name TrustedInstaller -ErrorAction SilentlyContinue).Id | Select-Object -First 1)

                    Write-Verbose "Получаем токен от TrustedInstaller"

                    [IntPtr] $Token_TI = Duplicate-ProcessToken -ProcessID $pidTI -TokenType 'Impersonation'

                    if ( -not (( "$Token_TI" -as [uint64] ) -and ( "$Token_TI" -gt 0 )) )
                    {
                        Write-Verbose "Токен не получен, Запускаем службу TrustedInstaller еще раз"

                        Start-Sleep -Milliseconds 500
                        # Токен не получен, Запускаем TrustedInstaller еще раз.
                        # TrustedInstaller мог быть запущенным и выключиться перед самым получением токена.
                        # 2 раза старт, а не ресстарт потому, что доступ на перезапуск есть не всегда, и его некорректно делать принудительно.
                        # А TrustedInstaller может завершиться в самый не подходящий момент, так как его время простоя равно 2 минутам.
                        Start-Service -Name TrustedInstaller -ErrorAction SilentlyContinue
                        [int] $pidTI = ((Get-Process -Name TrustedInstaller -ErrorAction SilentlyContinue).Id | Select-Object -First 1)

                        Write-Verbose "Получаем токен от TrustedInstaller еще раз"

                        [IntPtr] $Token_TI = Duplicate-ProcessToken -ProcessID $pidTI -TokenType 'Impersonation'
                    }
                }
                catch
                {
                    Write-Warning "$NameThisFunction`: Ошибка получения токена от TrustedInstaller!"

                    Write-Verbose "Сбрасываем Олицетворение за SYSTEM"

                    try { $Global:CurrentShell.Undo()    } catch {}
                    try { $Global:CurrentShell.Dispose() } catch {}

                    [bool] $Exit = $true ; Return
                }

                Write-Verbose "Сбрасываем Олицетворение за SYSTEM"

                try { $Global:CurrentShell.Undo()    } catch {}
                try { $Global:CurrentShell.Dispose() } catch {}

                if ( $Token_TI )
                {
                    Write-Verbose "Получаем идентификацию `$Global:Identity_TI с токеном от TrustedInstaller"

                    try
                    {
                        [PSObject] $Global:Identity_TI = [System.Security.Principal.WindowsIdentity]::new($Token_TI)
                    }
                    catch { Write-Warning "$NameThisFunction`: Ошибка, при создании идентификации с токеном от TrustedInstaller!" ; [bool] $Exit = $true ; Return }
                }
                else { Write-Warning "$NameThisFunction`: Ошибка, токен от TrustedInstaller не получен!" ; [bool] $Exit = $true ; Return }
            }
        }
    }

    Process
    {
        # Перехват ошибок в блоке Process, для выхода из функции,
        # без отображения ошибки тут, и передача ее в глобальный trap для отображения и записи в лог.
        trap { Write-Warning "$NameThisFunction`: Ошибка в Process: `n   $($_.CategoryInfo.Category): $($_.Exception.Message)" ; break }

        # Выход из функции, если была установлена переменная $Exit в блоке Begin.
        if ( $Exit ) { Return }

        if ( $Token -eq 'TI'  )
        {
            Write-Verbose "Олицетворяем себя за TrustedInstaller"

            try { $Global:Identity_TI.Impersonate() > $null }
            catch
            {
                Write-Warning "$NameThisFunction`: Ошибка Олицетворения себя за TrustedInstaller!" ; Return
            }

            [PSObject] $isCurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

            if (( $isCurrentIdentity.ImpersonationLevel -eq 'Impersonation' ) -and ( $isCurrentIdentity.IsSystem ) -and ( $isCurrentIdentity.Groups.Value -like 'S-1-5-80*' ))
            {
                Write-Verbose "Выполнено Олицетворение себя за TrustedInstaller"
            }
            else { Write-Warning "$NameThisFunction`: Ошибка, Олицетворение себя за TrustedInstaller НЕ выполнено!" }
        }
        elseif ( $Token -eq 'SYS' )
        {
            Write-Verbose "Олицетворяем себя за SYSTEM"

            try { $Global:Identity_SYS.Impersonate() > $null }
            catch
            {
                Write-Warning "$NameThisFunction`: Ошибка Олицетворения себя за SYSTEM!" ; Return
            }

            [PSObject] $isCurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

            if (( $isCurrentIdentity.ImpersonationLevel -eq 'Impersonation' ) -and ( $isCurrentIdentity.IsSystem ) -and ( $isCurrentIdentity.Groups.Value.Count -eq 3 ))
            {
                Write-Verbose "Выполнено Олицетворение себя за SYSTEM"
            }
            else { Write-Warning "$NameThisFunction`: Ошибка, Олицетворение себя за SYSTEM НЕ выполнено!" }
        }
    }
}



Add-Type -Path $SQLiteDll

Token-Impersonate -Token SYS

Stop-Service -Name 'StateRepository' -Force -ErrorAction Continue

[string] $FileDataBase = "$env:ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd"

if ( -not [System.IO.File]::Exists($FileDataBase) )
{ Write-Warning "`n   Не найден файл базы данных: `n   '$FileDataBase'`n " ; Get-Pause ; Exit } # Выход.



[string] $BackUpStateRepositoryFolder = "$CurrentRoot\Files\BackUP\$BuildOS\$ArchOS"
[string] $BackUpFile = "$BackUpStateRepositoryFolder\StateRepository-Machine.srd"

try { New-Item -ItemType Directory -Path \\?\$BackUpStateRepositoryFolder -Force -ErrorAction Stop > $null }
catch { Write-Warning "Ошибка при создании папки: '$BackUpStateRepositoryFolder'`n`t$($_.exception.Message)" ; Get-Pause ; Exit }

if ( -not [System.IO.File]::Exists($BackUpFile) )
{
    Write-Host "`n  Создание бэкапа файла StateRepository-Machine.srd:" -ForegroundColor White
    Write-Host "  Путь: \Files\BackUP\$BuildOS\$ArchOS\StateRepository-Machine.srd" -ForegroundColor DarkGray
    Copy-Item $FileDataBase -Destination $BackUpStateRepositoryFolder -Force
}


$SqlConnection = New-Object -TypeName 'System.Data.SQLite.SQLiteConnection'
$SqlConnection.ConnectionString = "Data Source=$FileDataBase"
$SqlConnection.Open()
$SqlCommand = $SqlConnection.CreateCommand()
#$SqlCommand.CommandTimeout = 1
$DataSet = New-Object -TypeName 'System.Data.DataSet'



if ( 1 -eq $Choice )
{
    Write-Host "`n   Экспорт списка приложений ..." -ForegroundColor White

    $SqlCommand.CommandText = 'SELECT IsInbox,PackageFullName FROM "main"."Package";
SELECT ApplicationUserModelId,Executable FROM "main"."CacheApplication"'
    $SqlAdapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $SqlCommand
    $DataSet.Reset()
    [void]$SqlAdapter.Fill($DataSet)

    $Appx = @()
    #$Appx = Get-AppxPackage -AllUsers | Where-Object { $false -eq $_.IsFramework } | Select-Object -Property SignatureKind,NonRemovable,Name,PublisherId,InstallLocation
    $Appx = Get-AppxPackage -AllUsers | Select-Object -Property SignatureKind,NonRemovable,Name,PublisherId,InstallLocation,IsFramework
    
    # вызов Get-AppxPackage или Get-AppxProvisionedPackage не даёт отключить базу, 
    # так как они используют её через службу репозитария, поэтому снова отключаем службу.
    # Stop-Service -Name 'StateRepository' -Force -ErrorAction Continue
    
    [int] $N = 0
    foreach ( $App in ( $Appx | Sort-Object SignatureKind,Name ))
    {
        $N++
        $Name = "$($App.Name)_"

        $IsInbox = $DataSet.tables[0].Where({ $_.PackageFullName -like "*$Name*" },'First',1).IsInbox
        $Executable = ( $DataSet.tables[1].Where({ $_.ApplicationUserModelId -like "*$Name*" }).Executable | Sort-Object -Unique ) -join ', '

        $Appx | Where-Object { $_.Name -eq $App.Name } | Add-Member -MemberType NoteProperty -name IsInbox -Value $IsInbox -Force
        $Appx | Where-Object { $_.Name -eq $App.Name } | Add-Member -MemberType NoteProperty -name Executable -Value $Executable -Force
        $Appx | Where-Object { $_.Name -eq $App.Name } | Add-Member -MemberType NoteProperty -name Num -Value $N -Force
    }

    $Appx | Sort-Object Num | Format-Table -Property Num,IsInbox,SignatureKind,NonRemovable,IsFramework,Name,InstallLocation,Executable | Out-File -Width 500 -FilePath $ExportListApps -Force

    Write-Output "=========== Далее имена установленных приложений из магазина: `n" | Out-File -FilePath $ExportListApps -Force -Append
    $Appx | Sort-Object Num | Where-Object { 'System' -ne $_.SignatureKind -and $false -eq $_.IsFramework } | Select-Object -property Name -ExpandProperty Name -Unique | Out-File -FilePath $ExportListApps -Force -Append
    
    Write-Output "`n=========== Далее имена общих компонентов для всех установленных приложений, Framework!: `n" | Out-File -FilePath $ExportListApps -Force -Append
    $Appx | Sort-Object Num | Where-Object { $true -eq $_.IsFramework } | Select-Object -property Name -ExpandProperty Name -Unique | Out-File -FilePath $ExportListApps -Force -Append

    Write-Output "`n=========== Далее имена Системных приложений, осторожно!: `n" | Out-File -FilePath $ExportListApps -Force -Append
    $Appx | Sort-Object Num | Where-Object { 'System' -eq $_.SignatureKind } | Select-Object -property Name -ExpandProperty Name -Unique | Out-File -FilePath $ExportListApps -Force -Append

    Start-Service -Name 'StateRepository' -ErrorAction Continue

    Token-Impersonate -Reset

    Write-Host "`n  Всё выполнено `n" -ForegroundColor Green

    Get-Pause
    Exit
}



if ( 777 -eq $Choice )
{
    if ( $PackNames.Count )
    {
        [int] $N = 0

        Write-Host "`n  Указанные приложения для удаления:`n" -ForegroundColor White
    
        $PackNames | ForEach-Object {
            $N++
            if ( 10 -gt $N ) { $Space = ' ' } else { $Space = '' }
            Write-Host "       $Space$N. " -ForegroundColor DarkGray -NoNewline
            Write-Host "$_"  -ForegroundColor Cyan
        }
    }
    else
    {
        Write-Host "`n  Не указаны приложения для удаления!`n" -ForegroundColor Yellow
    }

     #    Get-Pause
     #    Exit


    $SqlCommand.CommandText = 'SELECT type,name FROM "main".sqlite_master WHERE "type" like "trigger";
SELECT IsInbox,PackageFullName FROM "main"."Package"'
    $SqlAdapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $SqlCommand
    $DataSet.Reset()
    [void] $SqlAdapter.Fill($DataSet)

    [string[]] $TriggersFound = $DataSet.tables[0].Name.Where({$_ -like 'TRG_AFTER*UPDATE_Package_SRJournal'})
    if ( $TriggersFound.Count )
    {
        Write-Host "`n  Найденные тригеры в базе данных:`n" -ForegroundColor White
        $TriggersFound | ForEach-Object {
            Write-Host "    Тригер: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$_"  -ForegroundColor Cyan
        }
    }
    else
    {
        Write-Host "`n  Не найдены в базе данных блокирующие тригеры!`n" -ForegroundColor DarkYellow
    }

    [int] $IsInbox = 0

    # Получение имен удаляемых приложений без исключенных, если такие указаны.
    [psobject[]] $PacksTable = $DataSet.tables[1] | Where-Object {
            
            $_.PackageFullName -match ($PackNames -join '|') -and $(
                if ( $DoNotRemovePackNames ) { $_.PackageFullName -notmatch ( $DoNotRemovePackNames -join '|' ) } else { $true } ) 
        }

    if ( $PacksTable.Count )
    {
        Write-Host "`n  Найденные значения IsInbox в базе данных:`n" -ForegroundColor White
        $PacksTable | ForEach-Object {
            Write-Host "   IsInbox: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($_.IsInbox) "  -ForegroundColor Cyan -NoNewline
            Write-Host "| "  -ForegroundColor DarkGray -NoNewline
            Write-Host "$($_.PackageFullName)"  -ForegroundColor White

            if ( $_.IsInbox ) { $IsInbox = $_.IsInbox }
        }
    }
    else
    {
        Write-Host "`n  Не найдены в базе данных указанные приложения для удаления!`n" -ForegroundColor DarkYellow
    }



    if ( $SetIsInbox -ne $IsInbox )
    {
        Write-Host "`n  Выполнение действий с базой данных: `n" -ForegroundColor Magenta

        if ( $TriggerName = $DataSet.tables[0].Name.Where({$_ -like 'TRG_AFTER*UPDATE_Package_SRJournal'},'First',1) )
        {
            Write-Host "         Удаление тригера: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$TriggerName `n" -ForegroundColor Cyan

            $SqlCommand.CommandText = "DROP TRIGGER ""main"".""$TriggerName"""
            $SqlAdapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $SqlCommand
            [void] $SqlAdapter.Fill($DataSet)
        }
        else
        {
            Write-Host "`n  Нет блокирующих тригеров в базе данных!`n" -ForegroundColor DarkYellow
        }

        foreach ( $PackName in $PackNames )
        {
            # Получение значения IsInbox у удаляемого приложения, без исключенных, если такие указаны.
            [psobject] $GetIsInBox = ($DataSet.tables[1].Where({
                $_.PackageFullName -like "*$PackName*" -and $( 
                    if ( $DoNotRemovePackNames ) { $_.PackageFullName -notmatch ($DoNotRemovePackNames -join '|') } else { $true } )
            },'First',1)).IsInbox
        
            if (( $GetIsInBox -match "^[0-1]$" ) -and ( $SetIsInbox -ne $GetIsInBox ))
            {
                Write-Host "        Установка IsInbox: " -ForegroundColor DarkGray -NoNewline
                Write-Host "$SetIsInbox " -ForegroundColor Green -NoNewline
                Write-Host "| " -ForegroundColor DarkGray -NoNewline
                Write-Host "$PackName" -ForegroundColor Cyan

                # SQLite не учитывает в шаблоне LIKE символы подчёркивания, поэтому их надо экранировать.
                $SqlCommand.CommandText = "UPDATE ""main"".""Package"" SET ""IsInbox""=$SetIsInbox WHERE ""PackageFullName"" LIKE '%$($PackName.Replace('_','\_'))%' ESCAPE '\'"
                $SqlAdapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $SqlCommand
                [void] $SqlAdapter.Fill($DataSet)
            }
        }
    }
    else
    {
        Write-Host "`n  Выполнение действий с базой данных не требуется" -ForegroundColor Green
    }



    $SqlCommand.CommandText = 'SELECT type,name FROM "main".sqlite_master WHERE "type" like "trigger"'
    $SqlAdapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $SqlCommand
    $DataSet.Reset()
    [void] $SqlAdapter.Fill($DataSet)


    if (( $TriggerName -like 'TRG_AFTER*UPDATE_Package_SRJournal' ) -and ( -not $DataSet.tables[0].Name.Where({ $_ -like $TriggerName }) ))
    {
        Write-Host "`n   Восстановление тригера: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$TriggerName" -ForegroundColor Cyan

        $SqlCommand.CommandText = "CREATE TRIGGER $TriggerName AFTER UPDATE ON Package FOR EACH ROW BEGIN UPDATE Sequence SET LastValue=LastValue+1 WHERE Id=2 ;
INSERT INTO SRJournal(_Revision, _WorkId, ObjectType, Action, ObjectId, PackageIdentity, WhenOccurred, SequenceId)SELECT 1, workid(), 1, 2, NEW._PackageID, pi._PackageIdentityID, now(), s.LastValue FROM Sequence AS s CROSS JOIN PackageIdentity AS pi WHERE s.Id=2 AND pi.PackageFullName=NEW.PackageFullName; END;"
        $SqlAdapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $SqlCommand
        [void] $SqlAdapter.Fill($DataSet)
    }


    Write-Host "`n  Проверка результата в базе данных:" -ForegroundColor Green

    $SqlCommand.CommandText = 'SELECT type,name FROM "main".sqlite_master WHERE "type" like "trigger";
SELECT IsInbox,PackageFullName FROM "main"."Package"'
    $SqlAdapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $SqlCommand
    $DataSet.Reset()
    [void] $SqlAdapter.Fill($DataSet)

    [string[]] $TriggersFound = $DataSet.tables[0].Name.Where({$_ -like 'TRG_AFTER*UPDATE_Package_SRJournal'})
    if ( $TriggersFound.Count )
    {
        Write-Host "`n  Найденные тригеры в базе данных:`n" -ForegroundColor White
        $TriggersFound | ForEach-Object {
            Write-Host "    Тригер: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$_"  -ForegroundColor Cyan
        }
    }
    else
    {
        Write-Host "`n  Не найдены в базе данных блокирующие тригеры!`n" -ForegroundColor DarkYellow
    }

    # Получение данных удаляемых приложений, без исключенных, если такие указаны.
    [psobject[]] $PacksTable = $DataSet.tables[1] | Where-Object {
            
            $_.PackageFullName -match ($PackNames -join '|') -and $(
                if ( $DoNotRemovePackNames ) { $_.PackageFullName -notmatch ( $DoNotRemovePackNames -join '|' ) } else { $true } ) 
        }

    if ( $PacksTable.Count )
    {
        Write-Host "`n  Найденные значения IsInbox в базе данных:`n" -ForegroundColor White
        $PacksTable | ForEach-Object {
            Write-Host "   IsInbox: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($_.IsInbox) "  -ForegroundColor Cyan -NoNewline
            Write-Host "| "  -ForegroundColor DarkGray -NoNewline
            Write-Host "$($_.PackageFullName)"  -ForegroundColor White
        }
    }
    else
    {
        Write-Host "`n  Не найдены в базе данных указанные приложения для удаления!`n" -ForegroundColor DarkYellow
    }
}

Stop-Service -Name 'StateRepository' -Force -ErrorAction Continue

Write-Host "`n  Отключение файла базы данных: " -ForegroundColor DarkGray -NoNewline
Write-Host "$($FileDataBase | Split-Path -leaf )`n" -ForegroundColor White

[int] $Try = 0
do
{
    $Try++
    Write-Host "   Попытка: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$Try" -ForegroundColor White

    try { $SqlCommand.Cancel() } catch {}
    $SqlCommand.Dispose()
    try { $SqlConnection.Close() } catch {}
    $SqlConnection.Dispose()

    if ( $Try -ge 10 ) { Stop-Service -Name 'StateRepository' -Force -ErrorAction Continue }

    Start-Sleep -Milliseconds 200
}
until (( -not [System.IO.File]::Exists("$FileDataBase-shm") ) -or ( $Try -ge 30 ))

if ( $Try -ge 30 ) {
    Write-Host "`n  База данных не отключена" -ForegroundColor DarkYellow
}
else
{
    Write-Host "`n  База данных отключена" -ForegroundColor Green
}

Start-Service -Name 'StateRepository' -ErrorAction Continue

Token-Impersonate -Reset



if ( 777 -eq $Choice )
{
    Write-Host "`n  Удаление указанных приложений: " -ForegroundColor White

    [string] $Path = 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned'

    foreach ( $PackName in $PackNames )
    {
        [bool] $ProcessedProvisioned = $false
        [bool] $Processed = $false

        Write-Host "`n   Удаление: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$PackName"  -ForegroundColor Cyan

        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$PackName*" } |
            ForEach-Object {
                
                # Если указанное имя для исключения из удаления входит в состав имени полученного полного имени приложения, то пропустить его
                if ( $DoNotRemovePackNames -and $_.PackageName -match ($DoNotRemovePackNames -join '|' ))
                { Write-Host "     Пропуск удаления: $($_.PackageName) из-за исключения" -ForegroundColor Red ; Return }

                try
                {
                    Write-Host "     Удаление Remove-AppxProvisionedPackage: $($_.PackageName)" -ForegroundColor DarkGray

                    $_ | Remove-AppxProvisionedPackage -Online -ErrorAction Continue > $null
                }
                catch
                {
                    Write-Warning "Ошибка: `t$($_.exception.Message)"
                    if ( $_.exception.Message -like '*80070002*' ) { Write-Warning "Эта ошибка из-за зависимости установленных приложений от этого компонента" }
                }

                $ProcessedProvisioned = $true
            }
        
        if ( -not $ProcessedProvisioned ) { Write-Host "     Приложение не найдено в Get-AppxProvisionedPackage" -ForegroundColor DarkYellow }

        Get-AppxPackage -AllUsers | Where-Object { $_.PackageFamilyName -like "*$PackName*" } |
            ForEach-Object {

                # Если указанное имя для исключения из удаления входит в состав имени полученного полного имени приложения, то пропустить его 
                if ( $DoNotRemovePackNames -and $_.PackageFamilyName -match ($DoNotRemovePackNames -join '|' ))
                { Write-Host "     Пропуск удаления: $($_.PackageFamilyName) из-за исключения" -ForegroundColor Red ; Return }

                try
                {
                    Write-Host "     Удаление Remove-AppxPackage -AllUsers: $($_.PackageFamilyName)" -ForegroundColor DarkGray
                    
                    $_ | Remove-AppxPackage -AllUsers -ErrorAction Continue > $null
                    
                    if ( -not $_.IsFramework )
                    {
                        Write-Host "     Создание раздела: " -ForegroundColor DarkMagenta -NoNewline
                        Write-Host "$Path\$($_.PackageFamilyName)" -ForegroundColor DarkGray

                        New-Item -Path $Path\$($_.PackageFamilyName) -Force -ErrorAction SilentlyContinue > $null
                    }
                    else { Write-Host "     Пропуск создания раздела для Framework" -ForegroundColor DarkGray }
                }
                catch
                {
                    Write-Warning "Ошибка: `t$($_.exception.Message)"
                    if ( $_.exception.Message -like '*80070002*' ) { Write-Warning "Эта ошибка из-за зависимости установленных приложений от этого компонента" }
                }

                $Processed = $true
            }
       
        if ( -not $Processed ) { Write-Host "     Приложение не найдено в Get-AppxPackage -AllUsers" -ForegroundColor DarkYellow }
    }
}



Write-Host "`n  Всё выполнено `n" -ForegroundColor Green

Get-Pause
Exit



trap
{
    Write-Host "`n   !!! Произошла ошибка в главном скрипте !!!`n" -ForegroundColor White -BackgroundColor DarkRed
        
    Write-Warning "Ошибка: '`n   $($_.CategoryInfo.Category): $($_.Exception.Message)"
    Write-Output "`n" $Error
    Write-Host "`n Для выхода нажмите любую клавишу" -ForegroundColor Gray
    $host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
    Exit
}

