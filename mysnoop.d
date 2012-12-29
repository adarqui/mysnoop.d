/* mysnoop for debian linux's dtrace implementation, major hackjob, adarq.org -- Andrew Darqui */
#!/usr/sbin/dtrace -C -qs

#pragma D option quiet

char **a;
uintptr_t i;

BEGIN
{
	printf("%5s %5s %5s %10s %20s %s\n", "UID", "GID", "PID", "EXECFROM", "PROGRAM", "ARGUMENTS");
}

syscall::chdir:entry
/ arg0 != NULL /
{
	printf("%5i %5i %5i %10s %20s %s\n", uid, gid, pid, execname, "chdir", copyinstr(arg0));	
}

syscall::execve:entry
/ arg1 != NULL && arg0 != NULL /
{
	printf("%5i %5i %5i %10s %20s", uid, gid, pid, execname, copyinstr(arg0));
	a = copyin(arg1,88);
	i = 0;

	i = (a[1] && i == 0 ? 0 : 1);
	a[1] = (i == 0 ? a[1] : NULL);

	i = (a[2] && i == 0 ? 0 : 2);
	a[2] = (i == 0 ? a[2] : NULL);

	i = (a[3] && i == 0 ? 0 : 3);
	a[3] = (i == 0 ? a[3] : NULL);

    i = (a[4] && i == 0 ? 0 : 4);
    a[4] = (i == 0 ? a[4] : NULL);

    i = (a[5] && i == 0 ? 0 : 5);
    a[5] = (i == 0 ? a[5] : NULL);

    i = (a[6] && i == 0 ? 0 : 6);
    a[6] = (i == 0 ? a[6] : NULL);

    i = (a[7] && i == 0 ? 0 : 7);
    a[7] = (i == 0 ? a[7] : NULL);

    i = (a[8] && i == 0 ? 0 : 8);
    a[8] = (i == 0 ? a[8] : NULL);

/*
	printf("\na[1]=%x\na[2]=%x\na[3]=%x\n", (long)a[1], (long)a[2], (long)a[3]);
*/

    printf(" -> %s %s %s %s %s %s %s %s %s\n",
        a[0] != NULL ? copyinstr((uintptr_t)a[0]) : "",
        a[1] != NULL ? copyinstr((uintptr_t)a[1]) : "",
        a[2] != NULL ? copyinstr((uintptr_t)a[2]) : "",
		a[3] != NULL ? copyinstr((uintptr_t)a[3]) : "",
		a[4] != NULL ? copyinstr((uintptr_t)a[4]) : "",
		a[5] != NULL ? copyinstr((uintptr_t)a[5]) : "",
		a[6] != NULL ? copyinstr((uintptr_t)a[6]) : "",
		a[7] != NULL ? copyinstr((uintptr_t)a[7]) : "",
		a[8] != NULL ? copyinstr((uintptr_t)a[8]) : ""
	);

}
