import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Base64Image {
    public static void main(String[] args) {
        //从Base64编码转换为图片文件
        String strImg = "";
        GenerateImage(strImg, "./out.jpg");
    }

    // 将图片文件转化为字节数组字符串，并对其进行Base64编码处理
    public static String GetImageStr(String imgFilePath) {
        byte[] data = null;
        try {
            InputStream in = new FileInputStream(imgFilePath);
            data = new byte[in.available()];
            in.read(data);
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(data);
    }
    // 对字节数组字符串进行Base64解码并生成图片
    public static boolean GenerateImage(String imgStr, String imgFilePath) {
        if (imgStr == null)
            return false;
        BASE64Decoder decoder = new BASE64Decoder();
        try {
            byte[] bytes = decoder.decodeBuffer(imgStr);
            for (int i = 0; i < bytes.length; ++i) {
                // 调整异常数据
                if (bytes[i] < 0) {
                    bytes[i] += 256;
                }
            }
            OutputStream out = new FileOutputStream(imgFilePath);
            out.write(bytes);
            out.flush();
            out.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
