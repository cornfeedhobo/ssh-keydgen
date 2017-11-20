package main

import (
	"bytes"
	"testing"
)

func TestKeydgen(t *testing.T) {

	WorkFactor = 16384

	seed := "ssh-keydgen"

	testCases := []struct {
		Type    string
		Bits    int
		Curve   int
		Private []byte
		Public  []byte
	}{
		{
			Type: "dsa",
			Bits: 1024,
			Private: []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCheDsaSzK3qbBgq5atqTvoAx2erRzgt8RZgvaAflX7CKltaXec
Oh4TBvPQ4j9ilMUOnBTqWLKq7uHkadjptqsyICLMMGmOW4fEi6UgRFg/xdNh0FCJ
qBNbOVFp+9mTAqsUwGC1xpxbvoSWF1n0lSzRjl9i+6nY/kz0yA6eMmUlIwIVAPZm
hKvNVExuPXKOaslhzy4vUCARAoGATMoOfFZkPJMkLk/qawl7uv9pqENAy7jJv6PN
0vvpexrKJwPruh8I0lPzDgEotAWYJfkObNHTKtlmKa5tAEFI9zs1SdSpcct6NNro
c1cQygyqWdZb7+NezpeQyMquM7KlficLJ3v01MvgGlRO/qcRKYs+KjASLQhAD1De
3ZOYUCACgYAYqd7tkOfeWKeja2vvV2mho56QQCNdsxQMv/3h2HgFo6KqaHz34Xrl
9SMD3HvH99BUGrgHzobDz4zVMBq7/0JSxnGQQPamWQI0twqoWrp/mYoLm+Utv9ww
veZaCNcEBvP6N2Mbgd49eaVUuf7nvrhvPHEKaJT4YHpJ12JIPuFYaAIUTl5hPD0P
GALgBquOFOtlhO+aV98=
-----END DSA PRIVATE KEY-----
`),
			Public: []byte(`ssh-dss AAAAB3NzaC1kc3MAAACBAKF4OxpLMrepsGCrlq2pO+gDHZ6tHOC3xFmC9oB+VfsIqW1pd5w6HhMG89DiP2KUxQ6cFOpYsqru4eRp2Om2qzIgIswwaY5bh8SLpSBEWD/F02HQUImoE1s5UWn72ZMCqxTAYLXGnFu+hJYXWfSVLNGOX2L7qdj+TPTIDp4yZSUjAAAAFQD2ZoSrzVRMbj1yjmrJYc8uL1AgEQAAAIBMyg58VmQ8kyQuT+prCXu6/2moQ0DLuMm/o83S++l7GsonA+u6HwjSU/MOASi0BZgl+Q5s0dMq2WYprm0AQUj3OzVJ1Klxy3o02uhzVxDKDKpZ1lvv417Ol5DIyq4zsqV+Jwsne/TUy+AaVE7+pxEpiz4qMBItCEAPUN7dk5hQIAAAAIAYqd7tkOfeWKeja2vvV2mho56QQCNdsxQMv/3h2HgFo6KqaHz34Xrl9SMD3HvH99BUGrgHzobDz4zVMBq7/0JSxnGQQPamWQI0twqoWrp/mYoLm+Utv9wwveZaCNcEBvP6N2Mbgd49eaVUuf7nvrhvPHEKaJT4YHpJ12JIPuFYaA==
`),
		},
		{
			Type: "dsa",
			Bits: 2048,
			Private: []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIDVQIBAAKCAQEAxgH80101ZYs3zrvHr0lEhuxFqZD3WyRvIyS/xj6bwGKKxqAU
pr2fOWEj4W6wO5lN71NrcLedtXtbwJWTY5bYF/Aj/GefifywpvQw309LOwU+74LB
NQsay7OpgcU86suXeQy7JOHD6l7sOz99262qhw2LNZQHf54ZGzsNgsEBJpekDePO
NTbNbhvjLkXL61kjY+zSvibYfafXVU1HQuhs3mBQVMFy0nU7ql0xFa73II+8iX9O
uTVlYqi4gp7RhqXwxRkHdZIRyr2KaCVf+nBdhiOPQuHScesjPKVdZNXj2cZ2XUPe
wmIvMZhEbxMNLGf4k0ZwJBbGPsTI6A+6LuIvhQIhAKQePmj31rk4ypY9ohJF2gjp
jclPVrVrqxaeGzKZd8RtAoIBACcwspIeLlfZTnBq5v103XY/pA2BwxH/hDNz80f3
HV43aZxUc53ZnOCha4kbGEe/CFNz2WnExh0KoLgIINM3yck8MmZcoGmZeSMzCWIJ
DWIadn58pxliy/a8WGoX5Rh2kLgTnjmANzycL1TByrj6BpTlZrY0Ul9s23+5dNJT
tW2+ADGWcWG4IcKmND355ASCy7YJNI6LZOFJbiuokZaFwwl+ELxD0RkqoouXe/4k
Ce7T0SOzxbHHbm6SUg0EBUjPZEy9gdlK2eDCuK3UgcCUZZlkq4lf8cOfjuqBPthW
gWT93JczB7HTkmQHD5HCrmoN1eU4NeWNwRCJgqqBBfqjXtgCggEAeOC4lKuf1AQ0
21jWy0R8C8JF+ZWNx+9XN/DiXBiDR8rT1aOvbsUFGrF9Y/ksjNS+F3seudJcVadU
vZ1UgT8gZikuhqZuhwB31MTvB/6iuRSU+41+tiRy9SbxroueiN9szQ3nun8qkIIH
Oe2ELiQ76uZA+3HTAHc6l+uVCWQaP//f/xDnqj25GbBGN8FTtdiu52X4nH2vOKBB
cjglSnPWl7Ttgsg8Zw635oOB7nUQgiCP52dxKlW6yW+8YC+tN+BOYFP+lC/jlPfs
g3mX7earIgT2FlBFQeE2ddtfFB12+swACMjKHKj3B5RUaGZlWDd5cSohzz8AB1qg
nC3yKjFsOwIgakFJWxMXK/M9elBXEQiGuphdYGTa8M7n3Nqv9gWK7QY=
-----END DSA PRIVATE KEY-----
`),
			Public: []byte(`ssh-dss AAAAB3NzaC1kc3MAAAEBAMYB/NNdNWWLN867x69JRIbsRamQ91skbyMkv8Y+m8BiisagFKa9nzlhI+FusDuZTe9Ta3C3nbV7W8CVk2OW2BfwI/xnn4n8sKb0MN9PSzsFPu+CwTULGsuzqYHFPOrLl3kMuyThw+pe7Ds/fdutqocNizWUB3+eGRs7DYLBASaXpA3jzjU2zW4b4y5Fy+tZI2Ps0r4m2H2n11VNR0LobN5gUFTBctJ1O6pdMRWu9yCPvIl/Trk1ZWKouIKe0Yal8MUZB3WSEcq9imglX/pwXYYjj0Lh0nHrIzylXWTV49nGdl1D3sJiLzGYRG8TDSxn+JNGcCQWxj7EyOgPui7iL4UAAAAhAKQePmj31rk4ypY9ohJF2gjpjclPVrVrqxaeGzKZd8RtAAABACcwspIeLlfZTnBq5v103XY/pA2BwxH/hDNz80f3HV43aZxUc53ZnOCha4kbGEe/CFNz2WnExh0KoLgIINM3yck8MmZcoGmZeSMzCWIJDWIadn58pxliy/a8WGoX5Rh2kLgTnjmANzycL1TByrj6BpTlZrY0Ul9s23+5dNJTtW2+ADGWcWG4IcKmND355ASCy7YJNI6LZOFJbiuokZaFwwl+ELxD0RkqoouXe/4kCe7T0SOzxbHHbm6SUg0EBUjPZEy9gdlK2eDCuK3UgcCUZZlkq4lf8cOfjuqBPthWgWT93JczB7HTkmQHD5HCrmoN1eU4NeWNwRCJgqqBBfqjXtgAAAEAeOC4lKuf1AQ021jWy0R8C8JF+ZWNx+9XN/DiXBiDR8rT1aOvbsUFGrF9Y/ksjNS+F3seudJcVadUvZ1UgT8gZikuhqZuhwB31MTvB/6iuRSU+41+tiRy9SbxroueiN9szQ3nun8qkIIHOe2ELiQ76uZA+3HTAHc6l+uVCWQaP//f/xDnqj25GbBGN8FTtdiu52X4nH2vOKBBcjglSnPWl7Ttgsg8Zw635oOB7nUQgiCP52dxKlW6yW+8YC+tN+BOYFP+lC/jlPfsg3mX7earIgT2FlBFQeE2ddtfFB12+swACMjKHKj3B5RUaGZlWDd5cSohzz8AB1qgnC3yKjFsOw==
`),
		},
		{
			Type: "dsa",
			Bits: 3072,
			Private: []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIE1wIBAAKCAYEAkpyYuhZfg7mNEPlfEaC7pXyrDj7qwsawyvlXnEa4lvTnNEf4
w7zkqsOIZ3wlw7Sb76JLwd6WnbblsJ84Oo9K7kXiT9m8EVlD9igkIRRg5IS2MSI+
RGvejRhJoKmhpA86t4QfOxkBgUtj0amKR3R505eGqRGHNRyHbM1CEkvN/Kw0Bdqm
qJITGNoZSST42/eXaYFT0bXduKuOtXImzZFxrncSGO8sAX45JcanT0ToC5mbZgBX
BsVZwt/64ZgSUdV8gfADjR8Q4ZlhA8DfLzTIlc6A0cLimV4VQxf/rNgP6xr0FyRU
RZX+yilOmJstM8e/SqBmkdUQsJoUlwEY4vCvJcL5tAofG8E9OP8qr/Pwy4NOdgEH
vS0CEKS8MCxgF/Aj8bqD8zKnOqWHLQx4M60GN7ELnPHhPOv9L6TG5RYkozhFcwGW
/+fGUGASy0OxkYOI+p/EjobER65SHlCgr/46OlNtkyFsCuHPLEirUXH2C2SavryX
OBP8WJ3bA/rPib8/AiEApB4+aPfWuTjKlj2iEkXaCOmNyU9WtWurFp4bMpl3xG0C
ggGBAJANuzqx8u45PBj+s/6G0nx9vLYltRZnH9j2FTa5919o/jXUds1vtKURNA6j
VqGTGtRXzyGqrkgLRyAkCldwETTYZwmtA6IK9BLN7kLEaFtTATh1m6KqSK8Y1RXm
FG6TamukEjmWZOOKDHunm1NseFVSYm01vqKFv12Y6lS9XqBSXfotGvTugVr91ow8
6cv0lNT+XDwRDsf5oemYCvLV1EAlJSDkYQKxEOkPcdcXHhdOdUP8qU+URgaj1e0w
s2rqnkWQXxL1FMuN6t1tx/YNN6w763O7+S8+cbIc3XozzyYpnuma+JRk2rmMtpyU
h3X0k2a5zsBIax48MdZJJGtWVdGq00j7DU14pmLcrP3QB6EXZTc741eb2iDVYeYv
4yUT1wUfFmm5nU7vjNXJHXtBck0d9SWJNoWMWqbP/OOe0OHJ2Xv/tK+YYY/jmbvX
ijDEWjFO2N6wFtHqjrRjMTBnADMj9DRXuQr3RS/Soce66JRzLtr0RlK4UIq8XzXX
O8wm1gKCAYEAgnwotWBlvEiBGbiy4F9MZxQuqnLzR9BPy/RRixunCYke5QPnwls+
cyHBV5uRpjUJLiqT3HrytoGYyYzFctZPw31XcfGWMbo1ZW5JXF79k8LNTwX4Ldwt
3pX9FHFqAliL2fuIeHUQYMyujTfmqmzB8pcYjhzZ5nD8v+eKXuUCKPizfTVuIsqN
RSzZnbTYeXlxHczP0wOKra3Efm23MDcbh+gA+Ywzurr/rfc+BaARC09+v/1kZA4x
SGBpC+hFO9FNqnklnuSRbQaQEX9sBp0Ptiscpg5uAko9/LDGyX82m3qLTwJzsmWK
3iuevGBAe0cLi2ZNRSNfqX5GhR+iDNlSjZxGJqs+/0quVZI8QESyrK/7cv90KbJn
up7ydICb/LtvKdPqOpzhASEDENZ3SjKJ6RpjY4Yt9oYVrtjg+De8tKMO/T0UEoQe
ImShaiBv9mIwKbDDUfGJPf8LeqppcD82nwEeYM7QB3oi1CXnEvCAde9GSvVwwF/W
lkRP8KX8b3B7AiAv64SI1xTQQIhm4KB/Zi0ZCc1sg0GOTxkaXmPKFhvNxg==
-----END DSA PRIVATE KEY-----
`),
			Public: []byte(`ssh-dss AAAAB3NzaC1kc3MAAAGBAJKcmLoWX4O5jRD5XxGgu6V8qw4+6sLGsMr5V5xGuJb05zRH+MO85KrDiGd8JcO0m++iS8Help225bCfODqPSu5F4k/ZvBFZQ/YoJCEUYOSEtjEiPkRr3o0YSaCpoaQPOreEHzsZAYFLY9Gpikd0edOXhqkRhzUch2zNQhJLzfysNAXapqiSExjaGUkk+Nv3l2mBU9G13birjrVyJs2Rca53EhjvLAF+OSXGp09E6AuZm2YAVwbFWcLf+uGYElHVfIHwA40fEOGZYQPA3y80yJXOgNHC4pleFUMX/6zYD+sa9BckVEWV/sopTpibLTPHv0qgZpHVELCaFJcBGOLwryXC+bQKHxvBPTj/Kq/z8MuDTnYBB70tAhCkvDAsYBfwI/G6g/Mypzqlhy0MeDOtBjexC5zx4Tzr/S+kxuUWJKM4RXMBlv/nxlBgEstDsZGDiPqfxI6GxEeuUh5QoK/+OjpTbZMhbArhzyxIq1Fx9gtkmr68lzgT/Fid2wP6z4m/PwAAACEApB4+aPfWuTjKlj2iEkXaCOmNyU9WtWurFp4bMpl3xG0AAAGBAJANuzqx8u45PBj+s/6G0nx9vLYltRZnH9j2FTa5919o/jXUds1vtKURNA6jVqGTGtRXzyGqrkgLRyAkCldwETTYZwmtA6IK9BLN7kLEaFtTATh1m6KqSK8Y1RXmFG6TamukEjmWZOOKDHunm1NseFVSYm01vqKFv12Y6lS9XqBSXfotGvTugVr91ow86cv0lNT+XDwRDsf5oemYCvLV1EAlJSDkYQKxEOkPcdcXHhdOdUP8qU+URgaj1e0ws2rqnkWQXxL1FMuN6t1tx/YNN6w763O7+S8+cbIc3XozzyYpnuma+JRk2rmMtpyUh3X0k2a5zsBIax48MdZJJGtWVdGq00j7DU14pmLcrP3QB6EXZTc741eb2iDVYeYv4yUT1wUfFmm5nU7vjNXJHXtBck0d9SWJNoWMWqbP/OOe0OHJ2Xv/tK+YYY/jmbvXijDEWjFO2N6wFtHqjrRjMTBnADMj9DRXuQr3RS/Soce66JRzLtr0RlK4UIq8XzXXO8wm1gAAAYEAgnwotWBlvEiBGbiy4F9MZxQuqnLzR9BPy/RRixunCYke5QPnwls+cyHBV5uRpjUJLiqT3HrytoGYyYzFctZPw31XcfGWMbo1ZW5JXF79k8LNTwX4Ldwt3pX9FHFqAliL2fuIeHUQYMyujTfmqmzB8pcYjhzZ5nD8v+eKXuUCKPizfTVuIsqNRSzZnbTYeXlxHczP0wOKra3Efm23MDcbh+gA+Ywzurr/rfc+BaARC09+v/1kZA4xSGBpC+hFO9FNqnklnuSRbQaQEX9sBp0Ptiscpg5uAko9/LDGyX82m3qLTwJzsmWK3iuevGBAe0cLi2ZNRSNfqX5GhR+iDNlSjZxGJqs+/0quVZI8QESyrK/7cv90KbJnup7ydICb/LtvKdPqOpzhASEDENZ3SjKJ6RpjY4Yt9oYVrtjg+De8tKMO/T0UEoQeImShaiBv9mIwKbDDUfGJPf8LeqppcD82nwEeYM7QB3oi1CXnEvCAde9GSvVwwF/WlkRP8KX8b3B7
`),
		},
		{
			Type:  "ecdsa",
			Curve: 256,
			Private: []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFdpyZIKKncFyNcWd0ztpOOy2pmLTZbP2i4VFKLLrYlFoAoGCCqGSM49
AwEHoUQDQgAEOJENFRO2TyoE8WlHGmCYjB6QfB8Pv5MXxAXt+KI1DFFtSj+4w2Iz
H+T/rjbQtByA3M0RSx8yZnvaC/aXxV1VGw==
-----END EC PRIVATE KEY-----
`),
			Public: []byte(`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiRDRUTtk8qBPFpRxpgmIwekHwfD7+TF8QF7fiiNQxRbUo/uMNiMx/k/6420LQcgNzNEUsfMmZ72gv2l8VdVRs=
`),
		},
		{
			Type:  "ecdsa",
			Curve: 384,
			Private: []byte(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDbWxDkE4EofKPPcWOJ33Db6jiPykYCHYp1kw+Bm/gtU0rS5UwxfuzN
VsYUdL9LOSGgBwYFK4EEACKhZANiAATYkI5fqrE5DXIPHIZjMSF0X7WIKvhIRrpH
RMZDwhkwUi2eNoGMzFPwxniBbhPM1PqkZL08xzhYIQdxMMwfsycG+gikeZSH2pV5
ANSoiZJGAszGlBSYB3NZ6UGNj57G6Cw=
-----END EC PRIVATE KEY-----
`),
			Public: []byte(`ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBNiQjl+qsTkNcg8chmMxIXRftYgq+EhGukdExkPCGTBSLZ42gYzMU/DGeIFuE8zU+qRkvTzHOFghB3EwzB+zJwb6CKR5lIfalXkA1KiJkkYCzMaUFJgHc1npQY2PnsboLA==
`),
		},
		{
			Type:  "ecdsa",
			Curve: 521,
			Private: []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIA21sQ5BOBKHyjz3Fjid9w28r6VwE1yodah8KQHUY7gFMf0TCntiwN
RPBhHOsZxJn2V+3e4CV+dM1nHB2mt2CnqeOgBwYFK4EEACOhgYkDgYYABAEYEZbV
+XYRxzG4qo6/dheTqPk6k54EIr3EoLStWMwdp7sqzy3QGn1rm/1UoYzOaPd8TRlq
1UlnSCbHtfS8DziIXgCB2ws8NVgJFSe2LBLCp64T+c+izHOTR/B4Da+otgbOpNvH
JLNZ3MzxLO/mquTvi1Ea0iQ+t1W3ISKFKd2gGCrM1g==
-----END EC PRIVATE KEY-----
`),
			Public: []byte(`ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAEYEZbV+XYRxzG4qo6/dheTqPk6k54EIr3EoLStWMwdp7sqzy3QGn1rm/1UoYzOaPd8TRlq1UlnSCbHtfS8DziIXgCB2ws8NVgJFSe2LBLCp64T+c+izHOTR/B4Da+otgbOpNvHJLNZ3MzxLO/mquTvi1Ea0iQ+t1W3ISKFKd2gGCrM1g==
`),
		},
		{
			Type: "rsa",
			Bits: 1024,
			Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDwHSV5jcCJ12VbDYZkfwesod8YVCMF3yPBT0ZbPU0bejjza2cU
jgM7sOEZWtjy3Y1yEcoWy2ZALdPsLRAfg9+lB1VCiiBtF/oYBRCmcOeuzvib/0OS
Dz5ieOkuWODNN0pgL/i55iZVLrEHmrqRbOv+iFJxyCEViVEluBOFrIJaBQIDAQAB
AoGAAbnD5i69nn/8y326ZIiBLp1vNAaOxeEHqcD/GXLEVhk3xZAVCpHGtiwcQglk
G8K53IMCN824a2eo6T6dqgxRlCN8BQQlhuA0YTMS+mlS6peSBkmxd24mHY1+QweY
WjfaWwOGMQ1VtTuctohqjJoKSjHwNK2hHlc/Z8rSJ7VkJOECQQD57wGz2i5v4i2o
hju4I/k3mz0ncEfsHCF6HHXrsiNIXo1FnVnX05UKUsTTyQ2vhuk8t7tpw0FgE5x+
itwAkRoNAkEA9fEfl3lS6biUPOtxn5WOMWP4RTUOjv+haW5oEAgsz6Dj1IEb1Evr
czVq7X0wzcJxBucDo4EsjnlNUGP1d9gZ2QJABRpGFJ/ttscNW5Vx/q5tVh9LPlTi
gwWIAXA3UBqQ8ddMVxGBVhCxyEYsUo6WQvEkLeMqZlxgJ0//L+4x06kiuQJBAKPG
sBz0o+wUCFMRDpcQxqHJSrj7ffhn7psA9LdIWl7haxZF67xR2jbcKZqAtZEvnIjW
KawmBv/Rc1THW900wPECQBgCc3QvK2a6UxzHATSKS1UA+dbiPEXyBu8wSLkeqFVR
5HZUchmWIMMX7WrYvVE/ExzAcEaZSSIrYmpCIOGc480=
-----END RSA PRIVATE KEY-----
`),
			Public: []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDwHSV5jcCJ12VbDYZkfwesod8YVCMF3yPBT0ZbPU0bejjza2cUjgM7sOEZWtjy3Y1yEcoWy2ZALdPsLRAfg9+lB1VCiiBtF/oYBRCmcOeuzvib/0OSDz5ieOkuWODNN0pgL/i55iZVLrEHmrqRbOv+iFJxyCEViVEluBOFrIJaBQ==
`),
		},
		{
			Type: "ed25519",
			Private: []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
jUf4yHwOuK7bWxDkE4EofKPPcWOJ33DbyvpXATXKh1pAkMkRf90JaxTgKe4iX7o8
arThHM3k7GAOSjjGpkIpuw==
-----END OPENSSH PRIVATE KEY-----
`),
			Public: []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIECQyRF/3QlrFOAp7iJfujxqtOEczeTsYA5KOMamQim7
`),
		},
	}

	for _, tc := range testCases {

		var k = &Keydgen{
			Seed:  []byte(seed),
			Type:  KeyType(tc.Type),
			Bits:  tc.Bits,
			Curve: tc.Curve,
		}

		if _, err := k.GenerateKey(); err != nil {
			t.Errorf("error generating key: %s", err)
		}

		privBytes, err := k.MarshalPrivateKey()
		if err != nil || !bytes.Equal(privBytes, tc.Private) {
			t.Error("generated private key does not match expected byte slice\n" +
				"Expected:\n" +
				string(tc.Private) + "\n" +
				"Generated:\n" +
				string(privBytes) + "\n")
		}

		pubBytes, err := k.MarshalPublicKey()
		if err != nil || !bytes.Equal(pubBytes, tc.Public) {
			t.Error("generated public key does not match expected byte slice\n" +
				"Expected:\n" +
				string(tc.Public) + "\n" +
				"Generated:\n" +
				string(pubBytes) + "\n")
		}

	}

}
