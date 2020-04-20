    BEGIN {
      pausedlen=0;
      stacklen=0;
      nestlvl=0;
      ZHPE_START=1
      ZHPE_STOP=2
      ZHPE_STOP_ALL=3
      ZHPE_PAUSE_ALL=4
      ZHPE_RESTART_ALL=5
      ZHPE_STAMP=8

      # vn_measure_oh, vn_stamp_oh may be set using awk -v
      if (length(v0_measure_oh) == 0)
          v0_measure_oh=0;
      if (length(v0_stamp_oh) == 0)
          v0_stamp_oh=0;
      if (length(v0_basic_oh) == 0)
          v0_basic_oh=0;

      if (length(v1_measure_oh) == 0)
          v1_measure_oh=0;
      if (length(v1_stamp_oh) == 0)
          v1_stamp_oh=0;
      if (length(v1_basic_oh) == 0)
          v1_basic_oh=0;

      if (length(v2_measure_oh) == 0)
          v2_measure_oh=0;
      if (length(v2_stamp_oh) == 0)
          v2_stamp_oh=0;
      if (length(v2_basic_oh) == 0)
          v2_basic_oh=0;

      if (length(v3_measure_oh) == 0)
          v3_measure_oh=0;
      if (length(v3_stamp_oh) == 0)
          v3_stamp_oh=0;
      if (length(v3_basic_oh) == 0)
          v3_basic_oh=0;

      if (length(v4_measure_oh) == 0)
          v4_measure_oh=0;
      if (length(v4_stamp_oh) == 0)
          v4_stamp_oh=0;
      if (length(v4_basic_oh) == 0)
          v4_basic_oh=0;

      if (length(v5_measure_oh) == 0)
          v5_measure_oh=0;
      if (length(v5_stamp_oh) == 0)
          v5_stamp_oh=0;
      if (length(v5_basic_oh) == 0)
          v5_basic_oh=0;

      if (length(v6_measure_oh) == 0)
          v6_measure_oh=0;
      if (length(v6_stamp_oh) == 0)
          v6_stamp_oh=0;
      if (length(v6_basic_oh) == 0)
          v6_basic_oh=0;

      printf("v0_basic_oh was %d\n",v0_basic_oh);
      printf("v0_measure_oh was %d\n",v0_measure_oh);
      printf("v0_stamp_oh was %d\n",v0_stamp_oh);
      printf("v1_basic_oh was %d\n",v1_basic_oh);
      printf("v1_measure_oh was %d\n",v1_measure_oh);
      printf("v1_stamp_oh was %d\n",v1_stamp_oh);
      printf("v2_basic_oh was %d\n",v2_basic_oh);
      printf("v2_measure_oh was %d\n",v2_measure_oh);
      printf("v2_stamp_oh was %d\n",v2_stamp_oh);

      # arbitrarily prepare for up to 20 nesting levels
      for ( i=0; i <20; i++ )
      {
          nest_stamp_cnt[i]=0;
          nest_measure_cnt[i]=0;
      }
    }
    {
        if (($1 < 0 ) || ($1 > 99))
        {
          printf("#%s\n",$0);
        }
        else
        {
        if ($1 == ZHPE_START)
        {
            if (nestlvl > 0)
            {
                for ( i=0; i< nestlvl; i++)
                    nest_measure_cnt[i]++;
            }

            nestlvl++;

            stack[stacklen++] = $2;
            if  ($2 in ndata)
            {
               cur = ndata[$2] + 1;
            }
            else
            {
                cur = 0;
            }
            ndata[$2] = cur;
            data0[$2][cur]=$3;
            data1[$2][cur]=$4;
            data2[$2][cur]=$5;
            data3[$2][cur]=$6;
            data4[$2][cur]=$7;
            data5[$2][cur]=$8;
            data6[$2][cur]=$9;
        }
        else
        {
            if ($1 == ZHPE_STAMP)
            {
                if (nestlvl > 0)
                {
                    for ( i=0; i< nestlvl; i++)
                        nest_stamp_cnt[i]++;
                }

                printf("%d,%d,", $1, $2);
                printf("%d,", $3);
                printf("%d,", $4);
                printf("%d,", $5);
                printf("%d,", $6);
                printf("%d,", $7);
                printf("%d,", $8);
                printf("%d,", $9);
                printf("%d,", nest_measure_cnt[nestlvl]);
                printf("%d,", nest_stamp_cnt[nestlvl]);
                printf("%d,", nestlvl);
                printf("\n");
            }
        else
        {
            if ($1 == ZHPE_STOP)
            {
                stacklen--;
                nestlvl--;

                if (nestlvl > 0)
                {
                    for ( i=0; i< nestlvl; i++)
                        nest_measure_cnt[i]++;
                }

                cursubid = stack[stacklen];
                if ( cursubid != $2 )
                {
                    printf("# unmatched stop. expected %d, saw %d\n",cursubid2, $2);
                    if (nestlvl > 0)
                    {
                        for ( i=0; i< nestlvl; i++)
                            nest_measure_cnt[i]++;
                    }
                    stacklen++;
                    nestlvl++;
                } else {
                    cur = ndata[$2];
                    ndata[$2] = cur - 1;
                    printf("%d,%d,", $1, $2);
                    printf("%d,", ($3 - data0[$2][cur]) - \
                                        (v0_basic_oh + \
                                        (nest_stamp_cnt[nestlvl] * v0_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v0_measure_oh)));
                    printf("%d,", $4 - data1[$2][cur] - \
                                        v1_basic_oh - \
                                        (nest_stamp_cnt[nestlvl] * v1_stamp_oh) - \
                                        (nest_measure_cnt[nestlvl] * v1_measure_oh));
                    printf("%d,", $5 - data2[$2][cur] - \
                                        v2_basic_oh - \
                                        (nest_stamp_cnt[nestlvl] * v2_stamp_oh) - \
                                        (nest_measure_cnt[nestlvl] * v2_measure_oh));
                    printf("%d,", $6 - data3[$2][cur] - \
                                        v3_basic_oh - \
                                        (nest_stamp_cnt[nestlvl] * v3_stamp_oh) - \
                                        (nest_measure_cnt[nestlvl] * v3_measure_oh));
                    printf("%d,", $7 - data4[$2][cur] - \
                                        v4_basic_oh - \
                                        (nest_stamp_cnt[nestlvl] * v4_stamp_oh) - \
                                        (nest_measure_cnt[nestlvl] * v4_measure_oh));
                    printf("%d,", $8 - data5[$2][cur] - \
                                        v5_basic_oh - \
                                        (nest_stamp_cnt[nestlvl] * v5_stamp_oh) - \
                                        (nest_measure_cnt[nestlvl] * v5_measure_oh));
                    printf("%d,", $9 - data6[$2][cur] - \
                                        v6_basic_oh - \
                                        (nest_stamp_cnt[nestlvl] * v6_stamp_oh) - \
                                        (nest_measure_cnt[nestlvl] * v6_measure_oh));
                    printf("%d,", nest_measure_cnt[nestlvl]);
                    printf("%d,", nest_stamp_cnt[nestlvl]);
                    printf("%d,", nestlvl);
                    printf("\n");

                    nest_measure_cnt[nestlvl] = 0;
                    nest_stamp_cnt[nestlvl] = 0;
                }
            }
            else
            {
                if ($1 == ZHPE_STOP_ALL)
                {
                    printf("# STOP_ALL %d\n",stacklen);
                    while ( stacklen > 0 )
                    {
                        stacklen--;
                        nestlvl--;
                        cursubid = stack[stacklen];
                        cur = ndata[cursubid];
                        ndata[cursubid] = cur - 1;
                        printf("%s,%s,", ZHPE_STOP_ALL, cursubid);
                        printf("%d,", $3 - data0[cursubid][cur] - \
                                        (v0_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v0_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v0_measure_oh)));
                        printf("%d,", $4 - data1[cursubid][cur] - \
                                        (v1_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v1_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v1_measure_oh)));
                        printf("%d,", $5 - data2[cursubid][cur] - \
                                        (v2_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v2_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v2_measure_oh)));
                        printf("%d,", $6 - data3[cursubid][cur] - \
                                        (v3_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v3_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v3_measure_oh)));
                        printf("%d,", $7 - data4[cursubid][cur] - \
                                        (v4_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v4_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v4_measure_oh)));
                        printf("%d,", $8 - data5[cursubid][cur] - \
                                        (v5_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v5_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v5_measure_oh)));
                        printf("%d,", $9 - data6[cursubid][cur] - \
                                        (v6_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v6_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v6_measure_oh)));
                        printf("%d,", nest_measure_cnt[nestlvl]);
                        printf("%d,", nest_stamp_cnt[nestlvl]);
                        printf("%d,", nestlvl);
                        printf("\n");
                        nest_measure_cnt[nestlvl] = 0;
                        nest_stamp_cnt[nestlvl] = 0;
                    }
                    if (pausedlen > 0)
                    {
                        if (pausedlen > 0) {
                            printf("# CLEARING PAUSED %d: ",pausedlen);
                            i=pausedlen-1;
                            printf("%d",paused[i]);
                            for ( i=pausedlen-2; i >= 0; i-- )
                            {
                                printf(", %d",paused[i]);
                            }
                            printf("\n");
                        } else {
                            printf("# Clearing paused: nothing paused\n");
                        }

                        if (nestlvl > 0)
                        for ( i=0; i < nestlvl; i++)
                            nest_measure_cnt[i]++;

                        for ( i=pausedlen-1; i >= 0; i-- )
                        {
                            cursubid = paused[i];
                            stack[stacklen++] = cursubid;
                            if  (cursubid in ndata)
                            {
                               cur = ndata[cursubid] + 1;
                            }
                            else
                            {
                                cur = 0;
                            }
                            ndata[cursubid] = cur;
                            data0[cursubid][cur]=$3 - psave0[i];
                            data1[cursubid][cur]=$4 - psave1[i];
                            data2[cursubid][cur]=$5 - psave2[i];
                            data3[cursubid][cur]=$6 - psave3[i];
                            data4[cursubid][cur]=$7 - psave4[i];
                            data5[cursubid][cur]=$8 - psave5[i];
                            data6[cursubid][cur]=$9 - psave6[i];
                            nestlvl++;
                        }
                        pausedlen=0;

                        while ( stacklen > 0 )
                        {
                            stacklen--;
                            nestlvl--;
                            cursubid = stack[stacklen];
                            cur = ndata[cursubid];
                            ndata[cursubid] = cur - 1;
                            printf("%s,%s,", ZHPE_STOP_ALL, cursubid);
                            printf("%d,", $3 - data0[cursubid][cur] - \
                                            ((nest_stamp_cnt[nestlvl] * v0_stamp_oh) + \
                                            (nest_measure_cnt[nestlvl] * v0_measure_oh)));
                            printf("%d,", $4 - data1[cursubid][cur] - \
                                            ((nest_stamp_cnt[nestlvl] * v1_stamp_oh) + \
                                            (nest_measure_cnt[nestlvl] * v1_measure_oh)));
                            printf("%d,", $5 - data2[cursubid][cur] - \
                                            ((nest_stamp_cnt[nestlvl] * v2_stamp_oh) + \
                                            (nest_measure_cnt[nestlvl] * v2_measure_oh)));
                            printf("%d,", $6 - data3[cursubid][cur] - \
                                            ((nest_stamp_cnt[nestlvl] * v3_stamp_oh) + \
                                            (nest_measure_cnt[nestlvl] * v3_measure_oh)));
                            printf("%d,", $7 - data4[cursubid][cur] - \
                                            ((nest_stamp_cnt[nestlvl] * v4_stamp_oh) + \
                                            (nest_measure_cnt[nestlvl] * v4_measure_oh)));
                            printf("%d,", $8 - data5[cursubid][cur] - \
                                            ((nest_stamp_cnt[nestlvl] * v5_stamp_oh) + \
                                            (nest_measure_cnt[nestlvl] * v5_measure_oh)));
                            printf("%d,", $9 - data6[cursubid][cur] - \
                                            ((nest_stamp_cnt[nestlvl] * v6_stamp_oh) + \
                                            (nest_measure_cnt[nestlvl] * v6_measure_oh)));
                            printf("%d,", nest_measure_cnt[nestlvl]);
                            printf("%d,", nest_stamp_cnt[nestlvl]);
                            printf("%d,", nestlvl);
                            printf("\n");
                            nest_measure_cnt[nestlvl] = 0;
                            nest_stamp_cnt[nestlvl] = 0;
                        }
                    }
                }
                else
                {
                if ($1 == ZHPE_PAUSE_ALL)
                {
                    if (( pausedlen > 0 ) && (stacklen > 0))
                    {
                      printf("ERROR: Cannot nest stats_pause_all\n");
                    } else {
                        if (stacklen > 0)
                            pausedlen=stacklen;

                        foocnt=0;
                        while ( stacklen > 0 )
                        {
                            stacklen--;
                            nestlvl--;
                            cursubid = stack[stacklen];
                            cur = ndata[cursubid];
                            ndata[cursubid] = cur - 1;
                            psave0[foocnt] = ($3 - data0[cursubid][cur] - \
                                        (v0_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v0_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v0_measure_oh)));
                            psave1[foocnt] = ($4 - data1[cursubid][cur] - \
                                        (v1_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v1_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v1_measure_oh)));
                            psave2[foocnt] = ($5 - data2[cursubid][cur] - \
                                        (v2_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v2_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v2_measure_oh)));
                            psave3[foocnt] = ($6 - data3[cursubid][cur] - \
                                        (v3_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v3_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v3_measure_oh)));
                            psave4[foocnt] = ($7 - data4[cursubid][cur] - \
                                        (v4_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v4_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v4_measure_oh)));
                            psave5[foocnt] = ($8 - data5[cursubid][cur] - \
                                        (v5_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v5_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v5_measure_oh)));
                            psave6[foocnt] = ($9 - data6[cursubid][cur] - \
                                        (v6_measure_oh + \
                                        (nest_stamp_cnt[nestlvl] * v6_stamp_oh) + \
                                        (nest_measure_cnt[nestlvl] * v6_measure_oh)));
                            nest_measure_cnt[nestlvl] = 0;
                            nest_stamp_cnt[nestlvl] = 0;
                            paused[foocnt] = cursubid;
                            foocnt++;
                        }
                        if (pausedlen > 0) {
                            printf("# PAUSING %d: ",pausedlen);
                            i=pausedlen-1;
                            printf("%d",paused[i]);
                            for ( i=pausedlen-2; i >= 0; i-- )
                            {
                                printf(", %d",paused[i]);
                            }
                            printf("\n");
                        } else {
                            printf("# Pause_all: nothing to pause\n");
                        }
                    }
                } else {
                    if ($1 == ZHPE_RESTART_ALL)
                    {
                        if (pausedlen > 0) {
                            printf("# RESTART_ALL %d: ",pausedlen);
                            i=pausedlen-1;
                            printf("%d",paused[i]);
                            for ( i=pausedlen-2; i >= 0; i-- )
                            {
                                printf(", %d",paused[i]);
                            }
                            printf("\n");
                        } else {
                            printf("# RESTART_ALL: nothing paused\n");
                        }

                        if (nestlvl > 0)
                        for ( i=0; i < nestlvl; i++)
                            nest_measure_cnt[i]++;

                        for ( i=pausedlen-1; i >= 0; i-- )
                        {
                            cursubid = paused[i];
                            stack[stacklen++] = cursubid;
                            if  (cursubid in ndata)
                            {
                               cur = ndata[cursubid] + 1;
                            }
                            else
                            {
                                cur = 0;
                            }
                            ndata[cursubid] = cur;
                            data0[cursubid][cur]=$3 - psave0[i];
                            data1[cursubid][cur]=$4 - psave1[i];
                            data2[cursubid][cur]=$5 - psave2[i];
                            data3[cursubid][cur]=$6 - psave3[i];
                            data4[cursubid][cur]=$7 - psave4[i];
                            data5[cursubid][cur]=$8 - psave5[i];
                            data6[cursubid][cur]=$9 - psave6[i];
                            nestlvl++;
                        }
                        pausedlen=0;
                    } else {
                                printf("##%d,%d,", $1, $2);
                                printf("%d,", $3);
                                printf("%d,", $4);
                                printf("%d,", $5);
                                printf("%d,", $6);
                                printf("%d,", $7);
                                printf("%d,", $8);
                                printf("%d,", $9);
                                printf("%d,", nest_measure_cnt[nestlvl]);
                                printf("%d,", nest_stamp_cnt[nestlvl]);
                                printf("%d,", nestlvl);
                                printf("\n");
                            }
             } } } } } }
  }
  END {
          printf("# END: %d\n",stacklen);
          while ( stacklen > 0 )
          {
              stacklen--;
              nestlvl--;
              cursubid = stack[stacklen];
              cur = ndata[cursubid];
              ndata[cursubid] = cur - 1;
              printf("%s,%s,", ZHPE_STOP_ALL, cursubid);
              printf("%d,", $3 - data0[cursubid][cur]);
              printf("%d,", $4 - data1[cursubid][cur]);
              printf("%d,", $5 - data2[cursubid][cur]);
              printf("%d,", $6 - data3[cursubid][cur]);
              printf("%d,", $7 - data4[cursubid][cur]);
              printf("%d,", $8 - data5[cursubid][cur]);
              printf("%d,", $9 - data6[cursubid][cur]);
              printf("%d,", nest_measure_cnt[nestlvl] - 1);
              printf("%d,", nest_stamp_cnt[nestlvl]);
              printf("%d,", nestlvl);
              printf("\n");
              nest_measure_cnt[nestlvl] = 0;
              nest_stamp_cnt[nestlvl] = 0;
          }
          pausedlen=0;
   }
