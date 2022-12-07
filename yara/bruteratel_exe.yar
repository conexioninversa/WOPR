rule brc4_badger_strings
{
meta:
    author = "@domchell"
    description = "Identifies strings used in Badger v1.0.x rDLL, even while sleeping"
strings:
    $a = "bruteloader"
    $b = "bhttp_x64.dll"
condition:
    1 of them
}
