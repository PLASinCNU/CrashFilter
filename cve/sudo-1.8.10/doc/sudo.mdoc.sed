/^\.Li 0$/ {
N
s/^\.Li 0\nminutes\.$/unlimited./
}
/^\.It Fl a Ar type/,/BSD authentication\.$/ {
d
}
/^\.It Fl c Ar class/,/BSD login classes\.$/ {
d
}
/^\.Xr login_cap 3 ,$/d
/^BSD login class$/ {
N
/^BSD login class\n\.It$/d
}
/^\.It Fl r Ar role/,/^\.Ar role \.$/ {
d
}
/^\.It Fl t Ar type/,/derived from the role\.$/ {
d
}
/^SELinux role and type$/ {
N
/^SELinux role and type\n\.It$/d
}
/^Solaris project$/ {
N
N
N
/^Solaris project\n\.It\nSolaris privileges\n\.It$/d
}
/^\.Bk -words$/ {
    N
    /^.*\n\.Op Fl a Ar type/{;N;/^.*\n\.Ek$/d;};/^.*\n\.Op Fl c Ar class/{;N;/^.*\n\.Ek$/d;};/^.*\n\.Op Fl r Ar role/{;N;/^.*\n\.Ek$/d;};/^.*\n\.Op Fl t Ar type/{;N;/^.*\n\.Ek$/d;};
}
