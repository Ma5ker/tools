static int myrandom(int begin,int end){
    int gap = end - begin +1;
    srand((unsigned)time(0));
    int ret = random() % gap + begin;
    return ret;
}
