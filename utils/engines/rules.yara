/*
    VigilantOnion Cyber Intel Ruleset
    Targets: Malware, Ransomware, Stealers, and Leaks
    Excludes: Adult Content
*/

// --- SECTION 1: ANTI-PORN FILTER ---
rule filter_adult_content
{
    meta:
        description = "Assigns negative score to adult content"
        score = -1000
    strings:
        $p1 = "porn" nocase wide ascii
        $p2 = "sex" nocase wide ascii
        $p3 = "hentai" nocase wide ascii
        $p4 = "camgirl" nocase wide ascii
        $p5 = "escort" nocase wide ascii
    condition:
        any of them
}

// --- SECTION 2: MALWARE & STEALERS ---
rule malware_intel
{
    meta:
        description = "Detects Malware and Stealer advertisements or panels"
        score = 60
    strings:
        $s1 = "stealer" nocase wide ascii
        $s2 = "builder" nocase wide ascii
        $s3 = "fud crypter" nocase wide ascii
        $s4 = "botnet" nocase wide ascii
        $s5 = "redline" nocase wide ascii
        $s6 = "vidar" nocase wide ascii
        $s7 = "raccoon stealer" nocase wide ascii
        $s8 = "formbook" nocase wide ascii
    condition:
        2 of them
}

rule ransomware_leaks
{
    meta:
        description = "Detects Ransomware group leak sites and negotiations"
        score = 80
    strings:
        $r1 = "ransomware" nocase wide ascii
        $r2 = "encrypted your files" nocase wide ascii
        $r3 = "leak site" nocase wide ascii
        $r4 = "decryptor" nocase wide ascii
        $r5 = "data breach" nocase wide ascii
        $r6 = "press release" nocase wide ascii
        $r7 = "contact us to pay" nocase wide ascii
    condition:
        2 of them
}

// --- SECTION 3: ACCESS & EXPLOITS ---
rule initial_access
{
    meta:
        description = "Detects Initial Access Broker (IAB) activity"
        score = 50
    strings:
        $a1 = "rdp access" nocase wide ascii
        $a2 = "vnc access" nocase wide ascii
        $a3 = "shell access" nocase wide ascii
        $a4 = "domain admin" nocase wide ascii
        $a5 = "corporate network" nocase wide ascii
    condition:
        any of them
}

// --- SECTION 4: DATABASE & INFRASTRUCTURE ---
rule db_structure
{
    meta:
        author = "@KevTheHermit"
        score = 40
    strings:
        $a = "CREATE TABLE" nocase
        $b = "INSERT INTO" nocase
        $c = "VALUES" nocase
        $d = "ENGINE" nocase
        $e = "CHARSET" nocase
        $f = "NOT NULL" nocase
        $g = "varchar" nocase
        $h = "PRIMARY KEY"
    condition:
        5 of them
}

rule db_connection
{
    meta:
        author = "@KevTheHermit"
        score = 40
    strings:
        $a = /\b(mongodb|http|https|ftp|mysql|postgresql|oracle):\/\/(\S*):(\S*)@(\S*)\b/
    condition:
        $a
}

rule email_filter
{
    meta:
        author = "@kovacsbalu"
        score = 10
    strings:
        $email_add = /\b[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)*\.[a-zA-Z-]+[\w-]\b/
    condition:
        any of them
}
