rule brc4_badger_strings_data
{
meta:
    author = "@domchell"
    description = "Identifies strings from Brute Ratel v1.1"
strings:
    $a = "\"chkin\":"
condition:
    $a
}
