/**********************************************************************************************************************/
/**
 * @file            receiveTSN.c
 *
 * @brief           Demo listener for TRDP for DbD
 *
 * @note            Project: Safe4RAIL WP1
 *                  For this demo to work, the library must be compiled with TSN_SUPPORT defined!
 *
 * @author          Bernd Loehr, NewTec GmbH
 *
 * @remarks         Copyright NewTec GmbH, 2018. All rights reserved.
 *
 * $Id: receiveTSN.c 2400 2023-07-13 16:30:12Z peter-liesner $
 *
 *      PL 2023-07-13: Ticket #435 Cleanup VLAN and TSN for options for Linux systems
 *     CWE 2023-03-28: Ticket #342 Updating TSN / VLAN / RT-thread code
 *      AM 2022-12-01: Ticket #399 Abstract socket type (VOS_SOCK_T, TRDP_SOCK_T) introduced, vos_select function is not anymore called with '+1'
 *
 */

/***********************************************************************************************************************
 * INCLUDES
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined (POSIX)
#include <unistd.h>
#elif defined (WIN32)
#include "getopt.h"
#endif

#include "trdp_if_light.h"
#include "vos_utils.h"
#include "vos_thread.h"

/***********************************************************************************************************************
 * DEFINITIONS
 */
#define APP_VERSION         "1.0"

#define DATA_MAX            1432

/* TSN PD sample definition */
#define PD_COMID_TSN        1000u               /* 24byte string as payload                     */
#define PD_COMID_TSN_CYCLE  1000u               /* default in us (1000 = 0.001 sec)             */
#define PD_COMID_TSN_DEST   "239.1.1.3"         /* default target (MC group) for TSN PD         */
#define PD_COMID_TSN_VLAN   10u                 /* default VLAN ID for TSN PD                   */

/* Standard PD sample definition */
#define PD_COMID_STD        10000u              /* 24byte string as payload                     */
#define PD_COMID_STD_CYCLE  100000u             /* default in us (100000 = 0.1 sec)             */
#define PD_COMID_STD_DEST   "239.1.1.2"         /* default target (MC group) for standard PD    */
#define PD_COMID_STD_VLAN   0u                  /* no VLAN  (ID 0) for standard PD              */

#define PD_PAYLOAD_SIZE     24u                 /* fix for this sample */

/* Payload definition (Timestamp as TIMEDATE64 and in ASCII) */
typedef struct
{
    TIMEDATE64          sentTime;
    UINT64              padding;                /* align string to next 16 byte boundary for easy tcpdump analysis */
    CHAR8               timeString[16];
} GNU_PACKED LATENCY_PACKET_T;

#define PD_TSN_PAYLOAD_SIZE  sizeof(LATENCY_PACKET_T)
#define PD_STD_PAYLOAD_SIZE  sizeof(LATENCY_PACKET_T)

/* Global variable set definition */
typedef struct fdf_context
{
    TRDP_APP_SESSION_T  appHandle;          /*    Our identifier to the library instance    */
    TRDP_PUB_T          pubHandle;          /*    Our identifier to the publication         */
    TRDP_SUB_T          subHandle;          /*    Our identifier to the subscription        */
    void                *pDataSource;
    UINT32              sourceSize;
    void                *pDataTarget;
    UINT32              targetSize;
} FDF_APP_CONTEXT;

static int      gComThreadTsnRunning = TRUE;
static int      gComThreadStdRunning = TRUE;

static int      gVerbose = FALSE;

UINT8           *gpOutputBufferTsn;
UINT8           *gpOutputBufferStd;
UINT8           gExampleDataTsn[DATA_MAX]  = "TSN example data";
UINT8           gExampleDataStd[DATA_MAX]  = "Standard example data";

FDF_APP_CONTEXT gAppContextTsn = {NULL, NULL, NULL, gExampleDataTsn, PD_TSN_PAYLOAD_SIZE, NULL, 0u};
FDF_APP_CONTEXT gAppContextStd = {NULL, NULL, NULL, gExampleDataStd, PD_STD_PAYLOAD_SIZE, NULL, 0u};

/***********************************************************************************************************************
 * PROTOTYPES
 */
static void dbgOut (void *, TRDP_LOG_T, const CHAR8 *, const CHAR8 *, UINT16, const CHAR8 *);
static void usage (const char *);
static void myPDcallBack (void *, TRDP_APP_SESSION_T, const TRDP_PD_INFO_T *, UINT8 *, UINT32 );
static void *comThreadTsn (void *arg);
static void *comThreadStd (void *arg);

/**********************************************************************************************************************/
/** callback routine for TRDP logging/error output
 *
 *  @param[in]        pRefCon          user supplied context pointer
 *  @param[in]        category         Log category (Error, Warning, Info etc.)
 *  @param[in]        pTime            pointer to NULL-terminated string of time stamp
 *  @param[in]        pFile            pointer to NULL-terminated string of source module
 *  @param[in]        LineNumber       line
 *  @param[in]        pMsgStr          pointer to NULL-terminated string
 *  @retval           none
 */
static void dbgOut (
    void        *pRefCon,
    TRDP_LOG_T  category,
    const CHAR8 *pTime,
    const CHAR8 *pFile,
    UINT16      LineNumber,
    const CHAR8 *pMsgStr)
{
    const char *catStr[] = {"**Error:", "Warning:", "   Info:", "  Debug:", "   User:"};
    CHAR8       *pF = strrchr(pFile, VOS_DIR_SEP);

    if ((category == VOS_LOG_DBG) && !gVerbose)
    {
        return;
    }
    if (category == VOS_LOG_USR)
    {
        printf("%s %s %s",
               strrchr(pTime, '-') + 1,
               catStr[category],
               pMsgStr);
        return;
    }
    printf("%s %s %s:%d %s",
           strrchr(pTime, '-') + 1,
           catStr[category],
           (pF == NULL)? "" : pF + 1,
           LineNumber,
           pMsgStr);
}

/**********************************************************************************************************************/
/* Print a sensible usage message */
/**********************************************************************************************************************/
static void usage (const char *appName)
{
    printf("Usage of %s\n", appName);
    printf("This tool receives and displays TSN PD-PDU messages from 'sendTSN' (ComId 0 and 1000)\n"
           "Arguments are:\n"
           "-O <own IP address for TSN> (default INADDR_ANY)\n"
           "-o <own IP address for standard PD> (default INADDR_ANY)\n"
           "-T <target TSN (multicast) IP address> (default 239.1.1.3)\n"
           "-t <target standard (multicast) IP address> (default 239.1.1.2)\n"
           "-V <VLAN-ID for TSN> (default 10)\n"
           "-v <VLAN-ID for standard PD> (default 0 = no VLAN)\n"
           "-P <priority for TSN = PCP: 0..7> (default 7)\n"
           "-p <priority for standard PD = QoS: 0..7> (default 3)\n"
           "-C <cycle time for TSN> (default 1000 [µs])\n"
           "-c <cycle time for standard PD> (default 100000 [µs])\n"
           "-d debug output, be more verbose\n"
           "-h print usage\n"
           );
}

/**********************************************************************************************************************/
/** callback routine for receiving TRDP traffic
 *
 *  @param[in]      pRefCon         user supplied context pointer
 *  @param[in]      pMsg            pointer to header/packet infos
 *  @param[in]      pData           pointer to data block
 *  @param[in]      dataSize        pointer to data size
 *  @retval         none
 */
static void myPDcallBack (
    void                    *pRefCon,
    TRDP_APP_SESSION_T      appHandle,
    const TRDP_PD_INFO_T    *pMsg,
    UINT8                   *pData,
    UINT32                  dataSize)
{
    /*    Check why we have been called    */
    switch (pMsg->resultCode)
    {
       case TRDP_NO_ERR:
           if (pData && dataSize > 0)
           {
               switch (pMsg->comId)
               {

                    // #################################################################################
                    case PD_COMID_TSN:    /* TSN */
                    {
                        LATENCY_PACKET_T      *pReceivedDS = (LATENCY_PACKET_T *) pData;
                        VOS_TIMEVAL_T         tempTime;
                        VOS_TIMEVAL_T         latency;
                        static VOS_TIMEVAL_T  sLastLatency    = {0, 0};
                        INT64                 curJitter;
                        static UINT64         sAvgJitterSum   = 0;
                        static UINT32         sAvgJitterCount = 0;
                        struct tm             *curTimeTM;

                        vos_getRealTime(&latency);
                        tempTime.tv_usec  = (INT32)vos_ntohl((UINT32)pReceivedDS->sentTime.tv_usec);
                        tempTime.tv_sec   = vos_ntohl(pReceivedDS->sentTime.tv_sec);

                        /* Compute the latency */
                        if (timercmp(&latency, &tempTime, >) > 0)
                        {
                            vos_subTime(&latency, &tempTime);
                        }
                        else  /* the clocks are out of sync! */
                        {
                            curTimeTM = localtime(&tempTime.tv_sec);
                            vos_printLog(VOS_LOG_USR, "Sync Error: ComID %d coming from the future (%02d:%02d:%02d.%06d)\n",
                                         pMsg->comId, curTimeTM->tm_hour, curTimeTM->tm_min, curTimeTM->tm_sec, tempTime.tv_usec);
                          break;
                        }

                        /* compute the current jitter and average */
                        curJitter = labs((INT64) ((sLastLatency.tv_sec - latency.tv_sec) * 1000000) + sLastLatency.tv_usec - latency.tv_usec);
                        if (sAvgJitterCount > 0)
                        {
                            sAvgJitterSum += curJitter;
                        }
                        sLastLatency = latency;
                        sAvgJitterCount += 1;
                        if (sAvgJitterCount > 1000)           // reset average every 1000 packets
                        {
                            sAvgJitterCount = 1;
                            sAvgJitterSum = curJitter;
                        }
                        vos_printLog(VOS_LOG_USR, "Receive TSN PD ComID %d, %s, latency %dµs, jitter %dµs, average (%d) %dµs\n", 
                                   pMsg->comId, pReceivedDS->timeString, (latency.tv_sec * 1000000) + latency.tv_usec,
                                   curJitter, sAvgJitterCount, sAvgJitterSum / sAvgJitterCount);
                        break;

                  }

                  // #################################################################################
                  case PD_COMID_STD:   /* Standard PD */
                      vos_printLog(VOS_LOG_USR, "Receive Standard PD ComID %d (%u byte): \"%s\"\n", pMsg->comId, dataSize, pData);
                      break;

                  // #################################################################################
                  default:
                      vos_printLog(VOS_LOG_DBG, "Unexpected ComID %d received (%u byte)\n", pMsg->comId, dataSize);
                      break;
               }
           }
           break;

       case TRDP_TIMEOUT_ERR:
           /* The application can decide here if old data shall be invalidated or kept    */
           vos_printLog(VOS_LOG_WARNING, "> Packet timed out (ComID %d)\n", pMsg->comId);
           break;

       default:
           vos_printLog(VOS_LOG_ERROR, "> Error on packet received (ComID %d), err = %d\n", pMsg->comId, pMsg->resultCode);
           break;
    }
}

/**********************************************************************************************************************/
/* Communication thread for TSN PD                                                                                    */
/**********************************************************************************************************************/
static void *comThreadTsn (void *arg)
{
    TRDP_APP_SESSION_T appHandle = (TRDP_APP_SESSION_T) arg;

    gComThreadTsnRunning = 1;

    while (gComThreadTsnRunning)
    {
        TRDP_FDS_T  rfds;
        INT32       noDesc, rv;
        TRDP_TIME_T tv;

        FD_ZERO(&rfds);

        tlc_getInterval(appHandle, &tv, &rfds, &noDesc);

        //vos_printLog(VOS_LOG_USR, "noDesc: %d, fdset: 0x%x\n", noDesc, rfds.fds_bits[0]);

        rv = vos_select(noDesc, &rfds, NULL, NULL, &tv);

        //vos_printLog(VOS_LOG_USR, "rv    : %d, fdset: 0x%x\n", rv, rfds.fds_bits[0]);

        (void) tlc_process(appHandle, &rfds, &rv);

        //vos_printLog(VOS_LOG_USR, "fin rv: %d, fdset: 0x%x\n", rv, rfds.fds_bits[0]);
        //vos_printLogStr(VOS_LOG_USR, "------------------------------\n");
    }
    vos_printLogStr(VOS_LOG_INFO, "TSN Comm thread ran out. \n");
    return NULL;
}

/**********************************************************************************************************************/
/* Communication thread for Standard PD                                                                               */
/**********************************************************************************************************************/
static void *comThreadStd (void *arg)
{
    TRDP_APP_SESSION_T appHandle = (TRDP_APP_SESSION_T) arg;

    gComThreadStdRunning = 1;

    while (gComThreadStdRunning)
    {
        TRDP_FDS_T  rfds;
        INT32       noDesc, rv;
        TRDP_TIME_T tv;

        FD_ZERO(&rfds);

        tlc_getInterval(appHandle, &tv, &rfds, &noDesc);

        //vos_printLog(VOS_LOG_USR, "noDesc: %d, fdset: 0x%x\n", noDesc, rfds.fds_bits[0]);

        rv = vos_select(noDesc, &rfds, NULL, NULL, &tv);

        //vos_printLog(VOS_LOG_USR, "rv    : %d, fdset: 0x%x\n", rv, rfds.fds_bits[0]);

        (void) tlc_process(appHandle, &rfds, &rv);

        //vos_printLog(VOS_LOG_USR, "fin rv: %d, fdset: 0x%x\n", rv, rfds.fds_bits[0]);
        //vos_printLogStr(VOS_LOG_USR, "------------------------------\n");
    }
    vos_printLogStr(VOS_LOG_INFO, "Standard Comm thread ran out. \n");
    return NULL;
}

/**********************************************************************************************************************/
/** main entry
 *
 *  @retval         0        no error
 *  @retval         1        some error
 */
int main (int argc, char *argv[])
{
    unsigned int            ip[4];
    TRDP_ERR_T              err;
    TRDP_PD_CONFIG_T pdConfigTsn = {NULL,
                                    NULL,
                                    {TRDP_PD_DEFAULT_TSN_PRIORITY, TRDP_PD_DEFAULT_TTL, 0u}, 
                                    TRDP_FLAGS_TSN, 
                                    TRDP_PD_DEFAULT_TIMEOUT, 
                                    TRDP_TO_DEFAULT, 
                                    TRDP_PD_UDP_PORT};
    TRDP_PD_CONFIG_T pdConfigStd = {NULL,
                                    NULL, 
                                    TRDP_PD_DEFAULT_SEND_PARAM, 
                                    TRDP_FLAGS_DEFAULT, 
                                    TRDP_PD_DEFAULT_TIMEOUT, 
                                    TRDP_TO_DEFAULT, 
                                    TRDP_PD_UDP_PORT};
    TRDP_PROCESS_CONFIG_T   processConfigTsn    = {"receiveTSN", "", "", PD_COMID_TSN_CYCLE, 255, TRDP_OPTION_BLOCK, PD_COMID_TSN_VLAN};
    TRDP_PROCESS_CONFIG_T   processConfigStd    = {"receiveSTD", "", "", PD_COMID_STD_CYCLE, 255, TRDP_OPTION_BLOCK, PD_COMID_STD_VLAN};
    UINT32                  ownIPtsn   = VOS_INADDR_ANY;
    UINT32                  ownIPstd   = VOS_INADDR_ANY;
    UINT32                  destIPtsn  = vos_dottedIP(PD_COMID_TSN_DEST);
    UINT32                  destIPstd  = vos_dottedIP(PD_COMID_STD_DEST);
    VOS_THREAD_T            myComThreadTsn;
    VOS_THREAD_T            myComThreadStd;
    UINT32                  pdTsn_cycleTime = PD_COMID_TSN_CYCLE;
    UINT32                  pdStd_cycleTime = PD_COMID_STD_CYCLE;
    int                     ch;
    CHAR8                   tempIP1[16];
    CHAR8                   tempIP2[16];

    while ((ch = getopt(argc, argv, "O:o:T:t:V:v:P:p:C:c:dh?")) != -1)
    {
        switch (ch)
        {
           case 'O':
           {   /* own IP for TSN PD */
               if (sscanf(optarg, "%u.%u.%u.%u",
                          &ip[3], &ip[2], &ip[1], &ip[0]) < 4)
               {
                   usage(argv[0]);
                   exit(1);
               }
               ownIPtsn = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
               break;
           }
           case 'o':
           {   /* own IP for standard PD */
               if (sscanf(optarg, "%u.%u.%u.%u",
                          &ip[3], &ip[2], &ip[1], &ip[0]) < 4)
               {
                   usage(argv[0]);
                   exit(1);
               }
               ownIPstd = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
               break;
           }          
           case 'T':
           {   /* target (multicast) IP for TSN PD */
               if (sscanf(optarg, "%u.%u.%u.%u",
                          &ip[3], &ip[2], &ip[1], &ip[0]) < 4)
               {
                   usage(argv[0]);
                   exit(1);
               }
               destIPtsn = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
               break;
           }
           case 't':
           {   /* target (multicast) IP for standard PD */
               if (sscanf(optarg, "%u.%u.%u.%u",
                          &ip[3], &ip[2], &ip[1], &ip[0]) < 4)
               {
                   usage(argv[0]);
                   exit(1);
               }
               destIPstd = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
               break;
           }
           case 'V':
           {   /* VLAN ID for TSN */
               if (sscanf(optarg, "%hu", &processConfigTsn.vlanId) < 1)
               {
                   usage(argv[0]);
                   exit(1);
               }
               break;
           }
           case 'v':
           {   /* VLAN ID for standard PD (0 = no VLAN) */
               if (sscanf(optarg, "%hu", &processConfigStd.vlanId) < 1)
               {
                   usage(argv[0]);
                   exit(1);
               }
               break;
           }
           case 'P':
           {   /* priority (0..7) for TSN */
               if (sscanf(optarg, "%hhu", &pdConfigTsn.sendParam.qos) < 1)
               {
                   usage(argv[0]);
                   exit(1);
               }
               break;
           }
           case 'p':
           {   /* priority (0..7) for standard PD */
               if (sscanf(optarg, "%hhu", &pdConfigStd.sendParam.qos) < 1)
               {
                   usage(argv[0]);
                   exit(1);
               }
               break;
           }
           case 'C':
           {   /* TSN cycle time (µs) */
               if (sscanf(optarg, "%u", &pdTsn_cycleTime) < 1)
               {
                   usage(argv[0]);
                   exit(1);
               }
               processConfigTsn.cycleTime = pdTsn_cycleTime;
               break;
           }
           case 'c':
           {   /* standard PD cycle time (µs) */
               if (sscanf(optarg, "%u", &pdStd_cycleTime) < 1)
               {
                   usage(argv[0]);
                   exit(1);
               }
               processConfigStd.cycleTime = pdStd_cycleTime;
               break;
           }
           case 'd':
           {   /* enable debug output */
               gVerbose = TRUE;
               break;
           }
           case 'h':
           case '?':
           default:
               /* help */
               usage(argv[0]);
               return 1;
        }
    }

    /*    Init the library  */

    if (tlc_init(&dbgOut,                           /* logging    */
                 NULL,
                 NULL) != TRDP_NO_ERR)              /* Use application supplied memory    */
    {
        printf("Initialization error\n");
        return 1;
    }

    vos_printLogStr(VOS_LOG_USR, "------------------------------------------------------------\n");
    vos_printLog(VOS_LOG_USR, "     TSN cycle time:     %10uµs\n", pdTsn_cycleTime);
    vos_printLog(VOS_LOG_USR, "Standard cycle time:     %10uµs\n", pdStd_cycleTime);
    memcpy(tempIP1, vos_ipDotted(ownIPtsn), 16);
    memcpy(tempIP2, vos_ipDotted(destIPtsn), 16);
    vos_printLog(VOS_LOG_USR, "Subscribe to       TSN PD (%5u) from IP %s to IP %s, VLAN %u, prio %u\n", PD_COMID_TSN, tempIP2, tempIP1, processConfigTsn.vlanId, pdConfigTsn.sendParam.qos);
    memcpy(tempIP1, vos_ipDotted(ownIPstd), 16);
    memcpy(tempIP2, vos_ipDotted(destIPstd), 16);
    vos_printLog(VOS_LOG_USR, "Subscribe to  Standard PD (%5u) from IP %s to IP %s, VLAN %u, prio %u\n", PD_COMID_STD, tempIP2, tempIP1, processConfigStd.vlanId, pdConfigStd.sendParam.qos);
    struct timespec tempRealTime;
    (void)clock_gettime(CLOCK_REALTIME, &tempRealTime);
#ifdef CLOCK_MONOTONIC
    struct timespec tempMonoTime;
    (void)clock_gettime(CLOCK_MONOTONIC, &tempMonoTime);
#endif
    vos_printLog(VOS_LOG_USR, "CLOCK_REALTIME:  %10usec, %10uns used for TSN\n", tempRealTime.tv_sec, tempRealTime.tv_nsec);
#ifdef CLOCK_MONOTONIC
    vos_printLog(VOS_LOG_USR, "CLOCK_MONOTONIC: %10usec, %10uns not used, info only\n", tempMonoTime.tv_sec, tempMonoTime.tv_nsec);
#endif    
    vos_printLogStr(VOS_LOG_USR, "------------------------------------------------------------\n");



    /* Open the TSN session with the TRDP stack */
    if (tlc_openSession(&gAppContextTsn.appHandle,
                        ownIPtsn, 0u,           /* use default IP address           */
                        NULL,                   /* no Marshalling                   */
                        &pdConfigTsn, NULL,             /* system defaults for PD and MD    */
                        &processConfigTsn) != TRDP_NO_ERR)
    {
        vos_printLogStr(VOS_LOG_USR, "Initialization error on open TSN session\n");
        return 1;
    }

    /* Open the standard session with the TRDP stack */
    if (tlc_openSession(&gAppContextStd.appHandle,
                        ownIPstd, 0u,           /* use default IP address           */
                        NULL,                   /* no Marshalling                   */
                        &pdConfigStd, NULL,             /* system defaults for PD and MD    */
                        &processConfigStd) != TRDP_NO_ERR)
    {
        vos_printLogStr(VOS_LOG_USR, "Initialization error on open standard session\n");
        return 1;
    }



    /* create TSN communication thread */
    err = (TRDP_ERR_T) vos_threadCreateSync(&myComThreadTsn, "comThreadTsn",
                                        VOS_THREAD_POLICY_OTHER,
                                        VOS_THREAD_PRIORITY_DEFAULT,
                                        0u,         /*  interval for cyclic thread      */
                                        NULL,       /*  start time for cyclic threads   */
                                        0u,         /*  stack size (default 4 x PTHREAD_STACK_MIN)   */
                                        (VOS_THREAD_FUNC_T) comThreadTsn, gAppContextTsn.appHandle);

    if (err != TRDP_NO_ERR)
    {
        vos_printLog(VOS_LOG_USR, "TSN comThread could not be created (error = %d)\n", err);
        tlc_terminate();
        return 1;
    }

    /* create Standard communication thread */
    err = (TRDP_ERR_T) vos_threadCreateSync(&myComThreadStd, "comThreadStd",
                                        VOS_THREAD_POLICY_OTHER,
                                        VOS_THREAD_PRIORITY_DEFAULT,
                                        0u,         /*  interval for cyclic thread      */
                                        NULL,       /*  start time for cyclic threads   */
                                        0u,         /*  stack size (default 4 x PTHREAD_STACK_MIN)   */
                                        (VOS_THREAD_FUNC_T) comThreadStd, gAppContextStd.appHandle);

    if (err != TRDP_NO_ERR)
    {
        vos_printLog(VOS_LOG_USR, "Standard comThread could not be created (error = %d)\n", err);
        tlc_terminate();
        return 1;
    }



    /****************************************************************************/
    /*   Subscribe to standard PD                                               */
    /****************************************************************************/

    err = tlp_subscribe(gAppContextStd.appHandle,   /*    our application identifier               */
                        &gAppContextStd.subHandle,  /*    our subscription identifier              */
                        NULL,                       /*    user reference                           */
                        myPDcallBack,               /*    callback function                        */
                        0u,                         /*    serviceID = 0                            */
                        PD_COMID_STD,               /*    ComID                                    */
                        0u,                         /*    etbTopoCnt: local consist only           */
                        0u,                         /*    opTopoCnt                                */
                        VOS_INADDR_ANY,             /*    Source IP filter                         */
                        VOS_INADDR_ANY,             /*    2nd Source IP filter                     */
                        destIPstd,                  /*    Standard PD (IP or MC Group)             */
                        TRDP_FLAGS_CALLBACK | TRDP_FLAGS_FORCE_CB,       /*    TRDP flags          */
                        PD_COMID_STD_CYCLE * 3u,    /*    Time out in us                           */
                        TRDP_TO_SET_TO_ZERO         /*    delete invalid data on timeout           */
                        );

    if (err != TRDP_NO_ERR)
    {
        vos_printLogStr(VOS_LOG_ERROR, "Standard PD subscribe error\n");
        tlc_terminate();
        return 1;
    }


    /****************************************************************************/
    /*   Subscribe to TSN PD                                                    */
    /****************************************************************************/

    err = tlp_subscribe(gAppContextTsn.appHandle,   /*    our application identifier               */
                        &gAppContextTsn.subHandle,  /*    our subscription identifier              */
                        NULL,                       /*    user reference                           */
                        myPDcallBack,               /*    callback function                        */
                        0u,                         /*    serviceId                                */
                        PD_COMID_TSN,               /*    ComID                                    */
                        0u,                         /*    etbTopoCnt: local consist only           */
                        0u,                         /*    opTopoCnt                                */
                        VOS_INADDR_ANY,             /*    Source IP filter                         */
                        VOS_INADDR_ANY,             /*    2nd Source IP filter                     */
                        destIPtsn,                  /*    MC Group to subscribe                    */
                        TRDP_FLAGS_CALLBACK | TRDP_FLAGS_FORCE_CB | TRDP_FLAGS_TSN, /* TRDP flags  */
                        pdTsn_cycleTime * 3u,       /*    Time out in us                           */
                        TRDP_TO_SET_TO_ZERO         /*    delete invalid data on timeout           */
                        );

    if (err != TRDP_NO_ERR)
    {
        vos_printLogStr(VOS_LOG_ERROR, "TSN PD subscribe error\n");
        tlc_terminate();
        return 1;
    }




    /****************************************************************************/
    /* Enter the main loop.                                                     */
    /****************************************************************************/

    vos_printLogStr(VOS_LOG_DBG, "Enter the main loop...\n\n");

    while (gComThreadStdRunning)
    {
        /* Just idle... */
        (void) vos_threadDelay(2 * PD_COMID_STD_CYCLE);
    }

    /*
     *    We always clean up behind us!
     */

    gComThreadTsnRunning = FALSE;
    gComThreadStdRunning = FALSE;

    tlp_unpublish(gAppContextTsn.appHandle, gAppContextTsn.pubHandle);
    tlp_unpublish(gAppContextStd.appHandle, gAppContextStd.pubHandle);
    tlc_closeSession(gAppContextTsn.appHandle);
    tlc_closeSession(gAppContextStd.appHandle);
    tlc_terminate();

    return 0;
}
