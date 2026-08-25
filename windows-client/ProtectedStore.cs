using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Csqtt.Windows;

/// <summary>
/// Минимальная обёртка над Windows Data Protection API (DPAPI).
/// DPAPI шифрует данные ключом профиля текущего пользователя, поэтому другой
/// пользователь или другой компьютер не сможет расшифровать сохранённый пароль.
/// </summary>
internal static partial class ProtectedStore
{
    // Нативный CryptProtectData принимает буфер в структуре DATA_BLOB.
    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob { public int Size; public nint Data; }

    [LibraryImport("crypt32.dll", EntryPoint = "CryptProtectData", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Protect(ref DataBlob input, string description, nint entropy, nint reserved, nint prompt, uint flags, out DataBlob output);

    [LibraryImport("crypt32.dll", EntryPoint = "CryptUnprotectData", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Unprotect(ref DataBlob input, nint description, nint entropy, nint reserved, nint prompt, uint flags, out DataBlob output);

    [LibraryImport("kernel32.dll", EntryPoint = "LocalFree")]
    private static partial nint LocalFree(nint memory);

    public static string Encrypt(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var bytes = Encoding.UTF8.GetBytes(value);
        var input = ToBlob(bytes);
        try
        {
            // Флаг 1 = CRYPTPROTECT_UI_FORBIDDEN: Windows не должна открывать
            // собственные диалоги во время фонового сохранения настроек.
            if (!Protect(ref input, "CSQTT configuration", 0, 0, 0, 1, out var output))
                // Резервный формат нужен для урезанных профилей Windows, где
                // DPAPI недоступен. Это только кодирование, а не шифрование.
                return "local:" + Convert.ToBase64String(bytes);
            try { var encrypted = new byte[output.Size]; Marshal.Copy(output.Data, encrypted, 0, output.Size); return "dpapi:" + Convert.ToBase64String(encrypted); }
            finally { LocalFree(output.Data); }
        }
        finally { Marshal.FreeHGlobal(input.Data); }
    }

    public static string Decrypt(string value)
    {
        // Префикс позволяет отличить DPAPI-буфер от резервного формата и
        // сохраняет совместимость с ранними сборками без префикса.
        if (string.IsNullOrEmpty(value)) return "";
        try
        {
            if (value.StartsWith("local:", StringComparison.Ordinal)) return Encoding.UTF8.GetString(Convert.FromBase64String(value[6..]));
            var encoded = value.StartsWith("dpapi:", StringComparison.Ordinal) ? value[6..] : value;
            var input = ToBlob(Convert.FromBase64String(encoded));
            try
            {
                if (!Unprotect(ref input, 0, 0, 0, 0, 1, out var output)) return "";
                try { var decrypted = new byte[output.Size]; Marshal.Copy(output.Data, decrypted, 0, output.Size); return Encoding.UTF8.GetString(decrypted); }
                finally { LocalFree(output.Data); }
            }
            finally { Marshal.FreeHGlobal(input.Data); }
        }
        catch { return ""; }
    }

    private static DataBlob ToBlob(byte[] bytes)
    {
        var pointer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, pointer, bytes.Length);
        return new DataBlob { Size = bytes.Length, Data = pointer };
    }
}
