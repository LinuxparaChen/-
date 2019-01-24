# APP启动流程

* **Launcher进程**
    
    ①Instrumentation.execStartActivity(Launcher调用Activity的start方法，调到了Instrumentation的execStartActivity方法)
    ```java
    //who = this(Activity)
    //contextThread = ApplicationThread
    //token = mToken(Binder)
    //target = this(Activity)
    //intent = 目标
    //requestCode = -1
    //options = null
    public ActivityResult execStartActivity(
            Context who, IBinder contextThread, IBinder token, Activity target,
            Intent intent, int requestCode, Bundle options) {
        IApplicationThread whoThread = (IApplicationThread) contextThread;
        Uri referrer = target != null ? target.onProvideReferrer() : null;
        if (referrer != null) {
            intent.putExtra(Intent.EXTRA_REFERRER, referrer);
        }
        ......
        try {
            intent.migrateExtraStreamToClipData();
            intent.prepareToLeaveProcess();
            //重要
            int result = ActivityManagerNative.getDefault()
                    .startActivity(whoThread, who.getBasePackageName(), intent,
                            intent.resolveTypeIfNeeded(who.getContentResolver()),
                            token, target != null ? target.mEmbeddedID : null,
                            requestCode, 0, null, options);
            checkStartActivityResult(result, intent);
        } catch (RemoteException e) {
            throw new RuntimeException("Failure from system", e);
        }
        return null;
    }
    ```
* **system_server进程**

    ①ActivityManagerService.startActivity(进程间通信Binder)
    
    (ActivityManagerNative.getDefault() = ActivityManagerProxy，ActivityManagerProxy的方法最终调用到ActivityManagerService）

    startActivity()-->startActivityAsUser()-->ActivityStackSupervisor.startActivityMayWait()-->startActivityLocked()-->startActivityUncheckedLocked()-->ActivityStack.startActivityLocked()-->ActivityStackSupervisor.resumeTopActivitiesLocked()-->ActivityStack.resumeTopActivitiesLocked()
    ```
    //caller = ApplicationThread(Launcher的)
    //callingUid = uid(Launcher的)
    //callingPackage = package(Launcher的)
    //intent = intent(包含目标类，包)
    //resolvedType = null
    //voiceSession = null
    //voiceInteractor = null
    //resultTo = Binder(Launcher)
    //resultWho = mEmbeddedID
    //requestCode = -1
    //startFlags = 0
    //profilerInfo = null
    //outResult = null
    //config = null
    //options = null
    //userid = 调用线程的userid
    //iContainer = null
    //inTask = null
    final int startActivityMayWait(IApplicationThread caller, int callingUid,
                                   String callingPackage, Intent intent, String resolvedType,
                                   IVoiceInteractionSession voiceSession, IVoiceInteractor voiceInteractor,
                                   IBinder resultTo, String resultWho, int requestCode, int startFlags,
                                   ProfilerInfo profilerInfo, WaitResult outResult, Configuration config,
                                   Bundle options, int userId, IActivityContainer iContainer, TaskRecord inTask) {
        ......

        int res = startActivityLocked(caller, intent, resolvedType, aInfo,
                voiceSession, voiceInteractor, resultTo, resultWho,
                requestCode, callingPid, callingUid, callingPackage,
                realCallingPid, realCallingUid, startFlags, options,
                componentSpecified, null, container, inTask);

        Binder.restoreCallingIdentity(origId);

        if (stack.mConfigWillChange) {
            
            mService.enforceCallingPermission(android.Manifest.permission.CHANGE_CONFIGURATION,
                    "updateConfiguration()");
            stack.mConfigWillChange = false;
            
            mService.updateConfigurationLocked(config, null, false, false);
        }

        if (outResult != null) {
            outResult.result = res;
            if (res == ActivityManager.START_SUCCESS) {
                mWaitingActivityLaunched.add(outResult);
                do {
                    try {
                        mService.wait();
                    } catch (InterruptedException e) {
                    }
                } while (!outResult.timeout && outResult.who == null);
            } else if (res == ActivityManager.START_TASK_TO_FRONT) {
                ActivityRecord r = stack.topRunningActivityLocked(null);
                if (r.nowVisible && r.state == ActivityState.RESUMED) {
                    outResult.timeout = false;
                    outResult.who = new ComponentName(r.info.packageName, r.info.name);
                    outResult.totalTime = 0;
                    outResult.thisTime = 0;
                } else {
                    outResult.thisTime = SystemClock.uptimeMillis();
                    mWaitingActivityVisible.add(outResult);
                    do {
                        try {
                            mService.wait();
                        } catch (InterruptedException e) {
                        }
                    } while (!outResult.timeout && outResult.who == null);
                }
            }
        }

        return res;
        
    }
    ```
    ```java
    final int startActivityLocked(IApplicationThread caller,
                                  Intent intent, String resolvedType, ActivityInfo aInfo,
                                  IVoiceInteractionSession voiceSession, IVoiceInteractor voiceInteractor,
                                  IBinder resultTo, String resultWho, int requestCode,
                                  int callingPid, int callingUid, String callingPackage,
                                  int realCallingPid, int realCallingUid, int startFlags, Bundle options,
                                  boolean componentSpecified, ActivityRecord[] outActivity, ActivityContainer container,
                                  TaskRecord inTask) {
        int err = ActivityManager.START_SUCCESS;

        ......
        //检查权限
        final int startAnyPerm = mService.checkPermission(
                START_ANY_ACTIVITY, callingPid, callingUid);
        final int componentPerm = mService.checkComponentPermission(aInfo.permission, callingPid,
                callingUid, aInfo.applicationInfo.uid, aInfo.exported);
        if (startAnyPerm != PERMISSION_GRANTED && componentPerm != PERMISSION_GRANTED) {
            ......//权限被拒绝。
        }

        ......
        //Activity记录
        ActivityRecord r = new ActivityRecord(mService, callerApp, callingUid, callingPackage,
                intent, resolvedType, aInfo, mService.mConfiguration, resultRecord, resultWho,
                requestCode, componentSpecified, this, container, options);
        if (outActivity != null) {
            outActivity[0] = r;
        }

        final ActivityStack stack = getFocusedStack();
        if (voiceSession == null && (stack.mResumedActivity == null
                || stack.mResumedActivity.info.applicationInfo.uid != callingUid)) {
            if (!mService.checkAppSwitchAllowedLocked(callingPid, callingUid,
                    realCallingPid, realCallingUid, "Activity start")) {
                ......
            }
        }

        ......
        
        doPendingActivityLaunchesLocked(false);

        err = startActivityUncheckedLocked(r, sourceRecord, voiceSession, voiceInteractor,
                startFlags, true, options, inTask);

        if (err < 0) {
            
            notifyActivityDrawnForKeyguard();
        }
        return err;
    }
    ```