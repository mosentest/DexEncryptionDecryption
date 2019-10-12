package com.ku.cn;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class CApplication extends Application {


    static String d = "1.1d1e1x1";//.dex
    static String dd = "1c1l1as1s1e1s.1d1e1x1";//classes.dex
    static String ddd = "1a1p1p"; //app
    static String dddd = "1d1e1xD1i1r1"; //dexDir

    static {
        d = d.replace("1", "");
        dd = dd.replace("1", "");
        ddd = ddd.replace("1", "");
        dddd = dddd.replace("1", "");
    }

    //定义好解密后的文件的存放路径
    private String app_name;

//    private String app_version;

//    private String TAG = this.getClass().getSimpleName();

    /**
     * ActivityThread创建Application之后调用的第一个方法
     * 可以在这个方法中进行解密，同时把dex交给android去加载
     */
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        CrashHandler.getInstance().init(base);
        //获取用户填入的metadata
        getMetaData();

        //得到当前加密了的APK文件
//        File apkFile=new File(Environment.getExternalStorageDirectory()+"/app-signed-aligned.apk");
        File apkFile = new File(getApplicationInfo().sourceDir);

        //把apk解压   app_name+"_"+app_version目录中的内容需要boot权限才能用
        File versionDir = getDir(base.getPackageName(), Context.MODE_PRIVATE);
        File appDir = new File(versionDir, ddd);
        File dexDir = new File(appDir, dddd);

        //得到我们需要加载的Dex文件
        List<File> dexFiles = new ArrayList<>();
        //进行解密（最好做MD5文件校验）
        if (!dexDir.exists() || dexDir.list().length == 0) {
            //把apk解压到appDir
            Zip.unZip(apkFile, appDir);
            //获取目录下所有的文件
            File[] files = appDir.listFiles();
            for (File file : files) {
                String name = file.getName();
                if (name.endsWith(d) && !TextUtils.equals(name, dd)) {
                    try {
                        //读取文件内容
                        byte[] bytes = ProxyUtils.getBytes(file);
                        //解密
                        byte[] decrypt = EncryptUtil.decrypt(bytes, EncryptUtil.ivBytes);
                        //写到指定的目录
                        FileOutputStream fos = new FileOutputStream(file);
                        fos.write(decrypt);
                        fos.flush();
                        fos.close();
                        dexFiles.add(file);

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        } else {
            for (File file : dexDir.listFiles()) {
                dexFiles.add(file);
            }
        }

        try {
            //2.把解密后的文件加载到系统
            loadDex(dexFiles, versionDir);
        } catch (Exception e) {
            e.printStackTrace();
        }


    }


    static String p = "2p2a2th2L2i2s2t2";//pathList
    static String p1 = "2d2e2x2El2e2m2e2n2t2s";//dexElements
    static String p2 = "2m2a2k2eP2a2t2h2E2le2m2e2n2t2s";//makePathElements
    static String p3 = "2m2a2ke2D2e2xE2l2e2m2e2n2ts2";//makeDexElements

    static {
        p = p.replace("2", "");
        p1 = p1.replace("2", "");
        p2 = p2.replace("2", "");
        p3 = p3.replace("2", "");
    }

    private void loadDex(List<File> dexFiles, File versionDir) throws Exception {
        //1.获取pathlist
        Field pathListField = ProxyUtils.findField(getClassLoader(), p);
        Object pathList = pathListField.get(getClassLoader());
        //2.获取数组dexElements
        Field dexElementsField = ProxyUtils.findField(pathList, p1);
        Object[] dexElements = (Object[]) dexElementsField.get(pathList);
        //3.反射到初始化dexElements的方法
        Method makeDexElements = null;
        Object[] addElements = null;
        ArrayList<IOException> suppressedExceptions = new ArrayList<IOException>();
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            makeDexElements = ProxyUtils.findMethod(pathList, p2, List.class, File.class, List.class);
            addElements = (Object[]) makeDexElements.invoke(pathList, dexFiles, versionDir, suppressedExceptions);
        } else if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            //DexPathList.java
            Method[] declaredMethods = pathList.getClass().getDeclaredMethods();
            for (Method declaredMethod : declaredMethods) {
                Class<?>[] parameterTypes = declaredMethod.getParameterTypes();
                //Log.i("mm", "declaredMethod name is:" + declaredMethod.getName() + ",parameterTypes:" + Arrays.toString(parameterTypes));
                if (p3.equals(declaredMethod.getName())) {
                    if (!declaredMethod.isAccessible()) {
                        declaredMethod.setAccessible(true);
                    }
                    makeDexElements = declaredMethod;
                    addElements = (Object[]) makeDexElements.invoke(pathList, dexFiles, versionDir, suppressedExceptions);
                    break;
                }
            }
//            makeDexElements = pathList.getClass().getDeclaredMethod(" makeDexElements", ArrayList.class, File.class, ArrayList.class);
//            addElements = (Object[]) makeDexElements.invoke(pathList, dexFiles, versionDir, suppressedExceptions);
        } else {
            Method[] declaredMethods = pathList.getClass().getDeclaredMethods();
            for (Method declaredMethod : declaredMethods) {
                Class<?>[] parameterTypes = declaredMethod.getParameterTypes();
                //Log.i("mm", "declaredMethod name is:" + declaredMethod.getName() + ",parameterTypes:" + Arrays.toString(parameterTypes));
                if (p3.equals(declaredMethod.getName())) {
                    if (!declaredMethod.isAccessible()) {
                        declaredMethod.setAccessible(true);
                    }
                    makeDexElements = declaredMethod;
                    addElements = (Object[]) makeDexElements.invoke(pathList, dexFiles, versionDir);
                    break;
                }
            }
//            makeDexElements = ProxyUtils.findMethod(pathList, " makeDexElements", ArrayList.class, File.class);
//            addElements = (Object[]) makeDexElements.invoke(pathList, dexFiles, versionDir);
        }

        //合并数组
        Object[] newElements = (Object[]) Array.newInstance(dexElements.getClass().getComponentType(), dexElements.length + addElements.length);
        System.arraycopy(dexElements, 0, newElements, 0, dexElements.length);
        System.arraycopy(addElements, 0, newElements, dexElements.length, addElements.length);

        //替换classloader中的element数组
        dexElementsField.set(pathList, newElements);
    }

    private void getMetaData() {
        try {
            ApplicationInfo applicationInfo = getPackageManager().getApplicationInfo(
                    getPackageName(), PackageManager.GET_META_DATA);
            Bundle metaData = applicationInfo.metaData;
            if (null != metaData) {
                if (metaData.containsKey("app_name")) {
                    app_name = metaData.getString("app_name");
                }
//                if (metaData.containsKey("app_version")) {
//                    app_version = metaData.getString("app_version");
//                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 开始替换application
     */
    @Override
    public void onCreate() {
        super.onCreate();
        try {
            bindRealApplicatin();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    boolean isBindReal;
    Application delegate;

    private void bindRealApplicatin() throws Exception {
        if (isBindReal) {
            return;
        }
        if (TextUtils.isEmpty(app_name)) {
            return;
        }
        //得到attachBaseContext(context) 传入的上下文 ContextImpl
        Context baseContext = getBaseContext();
        //创建用户真实的application (MyApplication)
        Class<?> delegateClass = Class.forName(app_name);
        delegate = (Application) delegateClass.newInstance();
        //得到attach()方法
        Method attach = Application.class.getDeclaredMethod("attach", Context.class);
        attach.setAccessible(true);
        attach.invoke(delegate, baseContext);


//        ContextImpl---->mOuterContext(app)   通过Application的attachBaseContext回调参数获取
        Class<?> contextImplClass = Class.forName("android.app.ContextImpl");
        //获取mOuterContext属性
        Field mOuterContextField = contextImplClass.getDeclaredField("mOuterContext");
        mOuterContextField.setAccessible(true);
        mOuterContextField.set(baseContext, delegate);

//        ActivityThread--->mAllApplications(ArrayList)       ContextImpl的mMainThread属性
        Field mMainThreadField = contextImplClass.getDeclaredField("mMainThread");
        mMainThreadField.setAccessible(true);
        Object mMainThread = mMainThreadField.get(baseContext);

//        ActivityThread--->>mInitialApplication
        Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
        Field mInitialApplicationField = activityThreadClass.getDeclaredField("mInitialApplication");
        mInitialApplicationField.setAccessible(true);
        mInitialApplicationField.set(mMainThread, delegate);
//        ActivityThread--->mAllApplications(ArrayList)       ContextImpl的mMainThread属性
        Field mAllApplicationsField = activityThreadClass.getDeclaredField("mAllApplications");
        mAllApplicationsField.setAccessible(true);
        ArrayList<Application> mAllApplications = (ArrayList<Application>) mAllApplicationsField.get(mMainThread);
        mAllApplications.remove(this);
        mAllApplications.add(delegate);

//        LoadedApk------->mApplication                      ContextImpl的mPackageInfo属性
        Field mPackageInfoField = contextImplClass.getDeclaredField("mPackageInfo");
        mPackageInfoField.setAccessible(true);
        Object mPackageInfo = mPackageInfoField.get(baseContext);

        Class<?> loadedApkClass = Class.forName("android.app.LoadedApk");
        Field mApplicationField = loadedApkClass.getDeclaredField("mApplication");
        mApplicationField.setAccessible(true);
        mApplicationField.set(mPackageInfo, delegate);

        //修改ApplicationInfo className   LooadedApk
        Field mApplicationInfoField = loadedApkClass.getDeclaredField("mApplicationInfo");
        mApplicationInfoField.setAccessible(true);
        ApplicationInfo mApplicationInfo = (ApplicationInfo) mApplicationInfoField.get(mPackageInfo);
        mApplicationInfo.className = app_name;

        delegate.onCreate();
        isBindReal = true;
    }

    /**
     * 让代码走入if中的第三段中
     *
     * @return
     */
    @Override
    public String getPackageName() {
        if (!TextUtils.isEmpty(app_name)) {
            return "";
        }
        return super.getPackageName();
    }

    @Override
    public Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException {
        if (TextUtils.isEmpty(app_name)) {
            return super.createPackageContext(packageName, flags);
        }
        try {
            bindRealApplicatin();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return delegate;

    }
}








