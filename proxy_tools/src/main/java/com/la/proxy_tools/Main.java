package com.la.proxy_tools;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;

public class Main {

    public static void main(String[] args) throws Exception {


        /**
         * 1.制作只包含解密代码的dex文件
         */
        makeDecodeDex();

        /**
         * 2.加密APK中所有的dex文件
         */
        encryptApkAllDex();

        /**
         * 3.把dex放入apk解压目录，重新压成apk文件
         */
        makeApk();


        /**
         * 4.对齐
         */
        zipalign();

        /**
         * 5. 签名打包
         */
        jksToApk();
    }


    public static void main1(String[] args) throws Exception {
        /**
         * 5. 签名打包
         */
        jksToApk();
    }

    /**
     * 1.制作只包含解密代码的dex文件
     */
    public static void makeDecodeDex() throws IOException, InterruptedException {
        File aarFile = new File("proxy_core/build/outputs/aar/proxy_core.aar");
        File aarTemp = new File("proxy_tools/temp");
        Zip.unZip(aarFile, aarTemp);
        File classesJar = new File(aarTemp, "classes.jar");
        File classesDex = new File(aarTemp, "classes.dex");
        //dx --dex --output out.dex in.jar
        //dx --dex --output D:\Downloads\android_space\DexDEApplication\proxy_tools\temp\classes.dex D:\Downloads\android_space\DexDEApplication\proxy_tools\temp\classes.jar

        //window
//        Process process = Runtime.getRuntime().exec("cmd /c dx --dex --output " + classesDex.getAbsolutePath()
//                + " " + classesJar.getAbsolutePath());

        //mac
        String cmd = "/Users/ziqimo/Library/Android/sdk/build-tools/27.0.3/dx --dex --output "
                + classesDex.getAbsolutePath() + " " + classesJar.getAbsolutePath();
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        process.waitFor();
        if (process.exitValue() != 0) {
            throw new RuntimeException("dex error");
        }

        System.out.println("makeDecodeDex--ok");
    }

    /**
     * 2.加密APK中所有的dex文件
     */
    public static void encryptApkAllDex() throws Exception {
        File apkFile = new File("app/build/outputs/apk/debug/app-debug.apk");
        File apkTemp = new File("app/build/outputs/apk/debug/temp");
        Zip.unZip(apkFile, apkTemp);
        //只要dex文件拿出来加密
        File[] dexFiles = apkTemp.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File file, String s) {
                return s.endsWith(".dex");
            }
        });
        //AES加密了
//        AES.init(AES.DEFAULT_PWD);
        for (File dexFile : dexFiles) {
            byte[] bytes = DexUtils.getBytes(dexFile);
            byte[] encrypt = EncryptUtil.encrypt(bytes, EncryptUtil.ivBytes);
            FileOutputStream fos = new FileOutputStream(new File(apkTemp,
                    System.currentTimeMillis() + dexFile.getName()));
            fos.write(encrypt);
            fos.flush();
            fos.close();
            dexFile.delete();

        }
        System.out.println("encryptApkAllDex--ok");
    }

    /**
     * 3.把dex放入apk解压目录，重新压成apk文件
     */
    private static void makeApk() throws Exception {
        File apkTemp = new File("app/build/outputs/apk/debug/temp");
        File aarTemp = new File("proxy_tools/temp");
        File classesDex = new File(aarTemp, "classes.dex");
        classesDex.renameTo(new File(apkTemp, "classes.dex"));
        File unSignedApk = new File("app/build/outputs/apk/debug/app-debug-unsigned.apk");
        Zip.zip(apkTemp, unSignedApk);
        System.out.println("makeApk--ok");
    }

    /**
     * 4. 对齐
     */
    private static void zipalign() throws IOException, InterruptedException {
        File unSignedApk = new File("app/build/outputs/apk/debug/app-debug-unsigned.apk");
        // zipalign -v -p 4 my-app-unsigned.apk my-app-unsigned-aligned.apk
        File alignedApk = new File("app/build/outputs/apk/debug/app-debug-unsigned-aligned.apk");

        //window
//        Process process = Runtime.getRuntime().exec("cmd /c zipalign -v -p  4 " + unSignedApk.getAbsolutePath()
        //mac
        String cmd = "/Users/ziqimo/Library/Android/sdk/build-tools/27.0.3/zipalign -v -p  4 " + unSignedApk.getAbsolutePath()
                + " " + alignedApk.getAbsolutePath();
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        process.waitFor();

        //zipalign -v -p 4 D:\Downloads\android_space\DexDEApplication\app\build\outputs\apk\debug\app-unsigned.apk D:\Downloads\android_space\DexDEApplication\app\build\outputs\apk\debug\app-unsigned-aligned.apk
//        System.out.println(process.waitFor() == 0 ? "zipalign成功" : "zipalign失败");

        System.out.println("zipalign---ok");
    }

    /**
     * 签名 打包
     *
     * @throws IOException
     */
    public static void jksToApk() throws IOException, InterruptedException {
        // apksigner sign --ks my-release-key.jks --out my-app-release.apk my-app-unsigned-aligned.apk
        //apksigner sign  --ks jks文件地址 --ks-key-alias 别名 --ks-pass pass:jsk密码 --key-pass pass:别名密码 --out  out.apk in.apk
        File signedApk = new File("app/build/outputs/apk/debug/app-debug-signed-aligned.apk");
        File jks = new File("proxy_tools/s20191127.jks");
        File alignedApk = new File("app/build/outputs/apk/debug/app-debug-unsigned-aligned.apk");
        //apksigner sign --ks D:\Downloads\android_space\DexDEApplication\proxy_tools\dexjks.jks --ks-key-alias yangkun --ks-pass pass:123123 --key-pass pass:123123 --out D:\Downloads\android_space\DexDEApplication\app\build\outputs\apk\debug\app-signed-aligned.apk D:\Downloads\android_space\DexDEApplication\app\build\outputs\apk\debug\app-unsigned-aligned.apk
        //apksigner sign --ks my-release-key.jks --out my-app-release.apk my-app-unsigned-aligned.apk

        //window
//        Process process = Runtime.getRuntime().exec("cmd /c  apksigner sign --ks " + jks.getAbsolutePath()
        //mac
        String cmd = "/Users/ziqimo/Library/Android/sdk/build-tools/27.0.3/apksigner sign --ks " + jks.getAbsolutePath()
                + " --ks-key-alias s20191127.jks --ks-pass pass:s20191127.jks --key-pass pass:s20191127.jks --out "
                + signedApk.getAbsolutePath() + " " + alignedApk.getAbsolutePath();
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        process.waitFor();
        if (process.exitValue() != 0) {
            throw new RuntimeException("dex error");
        }
        System.out.println("jksToApk----> ok");
    }
}
