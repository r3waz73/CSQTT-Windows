using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Csqtt.Windows;

/// <summary>
/// P/Invoke-описания функций из официальной библиотеки wintun.dll.
/// nint используется как непрозрачный нативный handle; разыменовывать его
/// напрямую нельзя — память пакетов копируется через Marshal.Copy.
/// </summary>
internal static partial class Wintun
{
    // Создание/открытие виртуального сетевого адаптера.
    [LibraryImport("wintun.dll", EntryPoint = "WintunCreateAdapter", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    internal static partial nint CreateAdapter(string name, string tunnelType, nint requestedGuid);
    [LibraryImport("wintun.dll", EntryPoint = "WintunOpenAdapter", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    internal static partial nint OpenAdapter(string name);
    [LibraryImport("wintun.dll", EntryPoint = "WintunCloseAdapter")] internal static partial void CloseAdapter(nint adapter);
    [LibraryImport("wintun.dll", EntryPoint = "WintunGetAdapterLUID")] internal static partial void GetAdapterLuid(nint adapter, out ulong luid);
    // Сессия владеет кольцевым буфером обмена пакетами с драйвером.
    [LibraryImport("wintun.dll", EntryPoint = "WintunStartSession", SetLastError = true)] internal static partial nint StartSession(nint adapter, uint capacity);
    [LibraryImport("wintun.dll", EntryPoint = "WintunEndSession")] internal static partial void EndSession(nint session);
    // Получение пакета из Windows и отправка пакета обратно в сетевой стек.
    [LibraryImport("wintun.dll", EntryPoint = "WintunReceivePacket", SetLastError = true)] internal static partial nint ReceivePacket(nint session, out uint size);
    [LibraryImport("wintun.dll", EntryPoint = "WintunReleaseReceivePacket")] internal static partial void ReleaseReceivePacket(nint session, nint packet);
    [LibraryImport("wintun.dll", EntryPoint = "WintunAllocateSendPacket", SetLastError = true)] internal static partial nint AllocateSendPacket(nint session, uint size);
    [LibraryImport("wintun.dll", EntryPoint = "WintunSendPacket")] internal static partial void SendPacket(nint session, nint packet);

    internal static void ThrowLast(string operation) => throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
}
