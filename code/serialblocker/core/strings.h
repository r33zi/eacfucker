#pragma once

FORCEINLINE SIZE_T StrLenW(const WCHAR* str)
{
    const WCHAR* s = str;
    while (*s) s++;
    return (SIZE_T)(s - str);
}

FORCEINLINE SIZE_T StrLenA(const char* str)
{
    const char* s = str;
    while (*s) s++;
    return (SIZE_T)(s - str);
}

FORCEINLINE int StrCmpNoCaseW(const WCHAR* a, const WCHAR* b)
{
    while (*a && *b) {
        WCHAR ca = (*a >= L'A' && *a <= L'Z') ? (*a + 0x20) : *a;
        WCHAR cb = (*b >= L'A' && *b <= L'Z') ? (*b + 0x20) : *b;
        if (ca != cb) return (ca > cb) ? 1 : -1;
        a++; b++;
    }
    return (*a) ? 1 : ((*b) ? -1 : 0);
}

FORCEINLINE int StrCmpA(const char* a, const char* b)
{
    while (*a && *b) {
        if (*a != *b) return (*a > *b) ? 1 : -1;
        a++; b++;
    }
    return (*a) ? 1 : ((*b) ? -1 : 0);
}

FORCEINLINE BOOLEAN StrStrLowerA(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return FALSE;
    SIZE_T hl = StrLenA(haystack);
    SIZE_T nl = StrLenA(needle);
    if (nl > hl) return FALSE;
    for (SIZE_T i = 0; i <= hl - nl; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < nl; j++) {
            char a = (haystack[i + j] >= 'A' && haystack[i + j] <= 'Z') ? 
                     (haystack[i + j] + 0x20) : haystack[i + j];
            char b = (needle[j] >= 'A' && needle[j] <= 'Z') ? 
                     (needle[j] + 0x20) : needle[j];
            if (a != b) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

FORCEINLINE VOID ZeroMem(PVOID dest, SIZE_T size)
{
    RtlZeroMemory(dest, size);
}

FORCEINLINE VOID CopyMem(PVOID dest, PVOID src, SIZE_T size)
{
    RtlCopyMemory(dest, src, size);
}