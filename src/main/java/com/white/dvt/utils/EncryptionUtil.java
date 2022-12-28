package com.white.dvt.utils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.Base64Utils;

/**
 * @author bergturing 202010/19
 */
public final class EncryptionUtil {

    private static final Charset CHARSET = StandardCharsets.UTF_8;

    private EncryptionUtil() {
    }

    /**
     * AES加密解密工具
     * @author bergturing 202010/19
     */
    public static final class Aes {
        private Aes() {
        }

        /**
         * 加密
         * @param aesKey 密钥key
         * @param str    待加密的字符串
         * @return 数据加密结果
         */
        public static String encrypt(String aesKey, String str) {
            ByteGroup byteCollector = new ByteGroup();
            byte[] randomStrBytes = getRandomStr().getBytes(CHARSET);
            byte[] textBytes = str.getBytes(CHARSET);
            byte[] networkBytesOrder = getNetworkBytesOrder(textBytes.length);

            // randomStr + networkBytesOrder + text
            byteCollector.addBytes(randomStrBytes)
                    .addBytes(networkBytesOrder)
                    .addBytes(textBytes);

            // ... + pad: 使用自定义的填充方式对明文进行补位填充
            byte[] padBytes = Pkcs7Encoder.encode(byteCollector.size());
            byteCollector.addBytes(padBytes);

            // 获得最终的字节流, 未加密
            byte[] unencrypted = byteCollector.toBytes();

            try {
                byte[] aesKeyBytes = Base64Utils.decodeFromUrlSafeString(aesKey);
                // 设置加密模式为AES的CBC模式
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
                IvParameterSpec iv = new IvParameterSpec(aesKeyBytes, 0, 16);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

                // 加密
                byte[] encrypted = cipher.doFinal(unencrypted);

                // 使用BASE64对加密后的字符串进行编码
                return Base64Utils.encodeToUrlSafeString(encrypted);
            } catch (Exception e) {
                throw new RuntimeException("aes加密失败", e);
            }
        }

        /**
         * 解密
         * @param aesKey  密钥key
         * @param echoStr 加密的字符串
         * @return 解密结果
         */
        public static String decrypt(String aesKey, String echoStr) {
            byte[] original;
            try {
                byte[] aesKeyBytes = Base64Utils.decodeFromUrlSafeString(aesKey);
                // 设置解密模式为AES的CBC模式
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
                IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKeyBytes, 0, 16));
                cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

                // 使用BASE64对密文进行解码
                byte[] encrypted = Base64Utils.decodeFromUrlSafeString(echoStr);

                // 解密
                original = cipher.doFinal(encrypted);
            } catch (Exception e) {
                throw new RuntimeException("aes解密失败", e);
            }

            try {
                // 去除补位字符
                byte[] bytes = Pkcs7Encoder.decode(original);

                // 分离16位随机字符串,网络字节序
                byte[] networkOrder = Arrays.copyOfRange(bytes, 16, 20);

                int xmlLength = recoverNetworkBytesOrder(networkOrder);

                return new String(Arrays.copyOfRange(bytes, 20, 20 + xmlLength), CHARSET);
            } catch (Exception e) {
                throw new RuntimeException("解密后得到的buffer非法", e);
            }
        }

        // 随机生成16位字符串
        private static String getRandomStr() {
            String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                int number = random.nextInt(base.length());
                sb.append(base.charAt(number));
            }
            return sb.toString();
        }

        /**
         * 生成4个字节的网络字节序
         * @param sourceNumber 源数据
         * @return 生成的4个字节的网络字节序
         */
        private static byte[] getNetworkBytesOrder(int sourceNumber) {
            byte[] orderBytes = new byte[4];
            orderBytes[3] = (byte) (sourceNumber & 0xFF);
            orderBytes[2] = (byte) (sourceNumber >> 8 & 0xFF);
            orderBytes[1] = (byte) (sourceNumber >> 16 & 0xFF);
            orderBytes[0] = (byte) (sourceNumber >> 24 & 0xFF);
            return orderBytes;
        }

        /**
         * 还原4个字节的网络字节序
         * @param orderBytes 4个字节的网络字节序
         * @return 还原的数据
         */
        private static int recoverNetworkBytesOrder(byte[] orderBytes) {
            int sourceNumber = 0;
            for (int i = 0; i < 4; i++) {
                sourceNumber <<= 8;
                sourceNumber |= orderBytes[i] & 0xff;
            }
            return sourceNumber;
        }

        /**
         * 字节组
         * @author bergturing 2020/09/25
         */
        private static final class ByteGroup {
            ArrayList<Byte> byteContainer = new ArrayList<>();

            public byte[] toBytes() {
                byte[] bytes = new byte[byteContainer.size()];
                for (int i = 0; i < byteContainer.size(); i++) {
                    bytes[i] = byteContainer.get(i);
                }
                return bytes;
            }

            public ByteGroup addBytes(byte[] bytes) {
                for (byte b : bytes) {
                    byteContainer.add(b);
                }
                return this;
            }

            public int size() {
                return byteContainer.size();
            }
        }

        /**
         * 提供基于PKCS7算法的加解密接口
         * @author bergturing 2020/09/25
         */
        private static final class Pkcs7Encoder {
            private static final int BLOCK_SIZE = 32;

            /**
             * 获得对明文进行补位填充的字节.
             * @param count 需要进行填充补位操作的明文字节个数
             * @return 补齐用的字节数组
             */
            public static byte[] encode(int count) {
                // 计算需要填充的位数
                int amountToPad = BLOCK_SIZE - (count % BLOCK_SIZE);
                // 获得补位所用的字符
                char padChr = chr(amountToPad);
                StringBuilder tmp = new StringBuilder();
                for (int index = 0; index < amountToPad; index++) {
                    tmp.append(padChr);
                }
                return tmp.toString().getBytes(CHARSET);
            }

            /**
             * 删除解密后明文的补位字符
             * @param decrypted 解密后的明文
             * @return 删除补位字符后的明文
             */
            static byte[] decode(byte[] decrypted) {
                int pad = decrypted[decrypted.length - 1];
                if (pad < 1 || pad > BLOCK_SIZE) {
                    pad = 0;
                }
                return Arrays.copyOfRange(decrypted, 0, decrypted.length - pad);
            }

            /**
             * 将数字转化成ASCII码对应的字符，用于对明文进行补码
             * @param a 需要转化的数字
             * @return 转化得到的字符
             */
            static char chr(int a) {
                byte target = (byte) (a & 0xFF);
                return (char) target;
            }

        }
    }

    /**
     * 签名工具类
     * @author bergturing 2020/10/19
     */
    public static final class Signature {
        private Signature() {
        }

        /**
         * 签名
         * @param token     签名token
         * @param timeStamp 时间戳
         * @param nonce     随机数
         * @param content   待签名的内容
         * @return 签名
         */
        public static String signature(String token, String timeStamp,
                                       String nonce, String content) throws Exception {
            return Sha1.getSha1(token, timeStamp, nonce, content);
        }

        /**
         * 校验签名
         * @param token     签名token
         * @param timeStamp 时间戳
         * @param nonce     随机数
         * @param content   待签名的内容
         * @param signature 签名
         * @return 校验结果 true 通过校验 false 未通过校验
         */
        public static boolean verify(String token, String timeStamp, String nonce,
                                     String content, String signature) throws Exception {
            return StringUtils.equals(signature, signature(token, timeStamp, nonce, content));
        }
    }

    /**
     * 计算消息签名接口
     * @author bergturing 2020/09/25
     */
    private static final class Sha1 {
        private Sha1() {
        }

        /**
         * 用SHA1算法生成安全签名
         * @param token     票据
         * @param timestamp 时间戳
         * @param nonce     随机字符串
         * @param encrypt   密文
         * @return 安全签名
         * @throws Exception 处理异常
         */
        public static String getSha1(String token, String timestamp, String nonce, String encrypt) throws Exception {
            try {
                String[] array = new String[]{token, timestamp, nonce, encrypt};
                StringBuilder sb = new StringBuilder();
                // 字符串排序
                Arrays.sort(array);
                for (int i = 0; i < 4; i++) {
                    sb.append(array[i]);
                }
                String str = sb.toString();
                // SHA1签名生成
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(str.getBytes());
                byte[] digest = md.digest();

                StringBuilder hexStr = new StringBuilder();
                String shaHex = "";
                for (byte b : digest) {
                    shaHex = Integer.toHexString(b & 0xFF);
                    if (shaHex.length() < 2) {
                        hexStr.append(0);
                    }
                    hexStr.append(shaHex);
                }
                return hexStr.toString();
            } catch (Exception e) {
                throw new Exception("sha加密生成签名失败", e);
            }
        }
    }
}
