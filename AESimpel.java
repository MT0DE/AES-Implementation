public class AESimpel {
    int nr = 4;


    public static void main(String[] args) {
        
    }

    static void HexToByteTest(){
        byte[] arr = HexStringToByteArray("FF");
        assert (arr[0] == (byte) 255);
    }
    static byte[] HexStringToByteArray(String hex){
        byte[] b = new byte[hex.length()/2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte)Integer.parseInt(hex.substring(i*2, i*2 + 2), 16);
        }
        return b;
    }
}