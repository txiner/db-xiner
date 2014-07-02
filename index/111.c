#include <stdio.h>
int main()
{
    FILE *fp;
    int i=617;
    char* s = "that is a good new";
    fp = fopen("text.dat","w");
    fputs("total",fp);
    fputs(":",fp);
    fprintf(fp,"%d\n",i);
    fprintf(fp,"%s",s);
    fclose(fp);
    return 0;
}
