/^\.Ss SELinux_Spec/,/^\.Ss [^S]/{;/^\.Ss [^S][^o][^l]/!d;};
/^On BSD systems/,/\.$/ {
d
}
/^\.It use_loginclass$/,/^\.It/ {
/^\.It [^u][^s][^e][^_][^l]/!d
}
s/Solaris_Priv_Spec? //
/^Solaris_Priv_Spec ::=/ {
N
d
}
/^\.It limitprivs$/,/^\.It/ {
/^\.It [^l][^i][^m][^i][^t]/!d
}
/^\.It privs$/,/^\.It/ {
/^\.It [^p][^r][^i][^v][^s]$/!d
}
/^On Solaris 10/,/^\.Pp/ {
d
}
s/SELinux_Spec? //
/^SELinux_Spec ::=/ {
N
d
}
/^\.It [rt][oy][lp]e$/,/^\.It/ {
/^\.It [^rt][^oy][^lp][^e]$/!d
}
