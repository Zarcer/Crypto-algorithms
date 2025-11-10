package cyber;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.security.MessageDigest;

public class SHA3 {

    public int rateBytes=136;
    public ArrayList<byte[]> messageBlocks=new ArrayList<>();
    long[][] state=new long[5][5];
    long[] roundConstant = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    int[][] rotationOffset = {
        {0, 36,  3, 41, 18},
        {1, 44, 10, 45,  2},
        {62,  6, 43, 15, 61},
        {28, 55, 25, 21, 56},
        {27, 20, 39,  8, 14}
    };

    /**
     * Padding part, divides entire message in blocks of 136 bytes, as sha-256 specs stated, puts between messages domain separator 01 and 10*1
     *
     * @param string to be padded
     */
    public void padding(byte[] string){
        int fullBlocks=string.length/rateBytes;
        int remainder=string.length%rateBytes;
        for(int i = 0;i<fullBlocks;i++){
            byte[] padded=Arrays.copyOfRange(string, i*rateBytes, (i+1)*rateBytes);
            messageBlocks.add(padded);
        }
        if(remainder==0){
            byte[] last = new byte[rateBytes];
            last[0] |= (byte) 0x06;
            last[rateBytes-1] |= (byte) 0x80;
            messageBlocks.add(last);
        }
        else{
            byte[] last = new byte[rateBytes];
            System.arraycopy(string, fullBlocks*rateBytes, last, 0, remainder);
            last[remainder] |= (byte) 0x06;
            last[rateBytes-1] |= (byte) 0x80;
            messageBlocks.add(last);
        }
    }

    /**
     * After padding, absorb part, writes message block into state, 136 bytes
     *
     * @param string
     */
    public void absorb(byte[] string){
        int lineCnt=rateBytes/8;
        for(int lineIndex=0;lineIndex<lineCnt;lineIndex++){
            int x= lineIndex%5;
            int y = lineIndex/5;
            long line=0L;
            int base=lineIndex*8;
            for(int b=0;b<8;b++){
                line |= (string[base + b] & 0xFFL) << (8*b);
            }
            state[x][y]^=line;
        }
    }

    /**
     * Permutation, 5 steps, 24 rounds
     * theta, computes parity, combines it with other columns
     * rho, just left rotate with hard-coded constant
     * pi, changes position of lines in state, so they will be distributed across all state
     * chi, makes state non-linear using logical formula
     * iota, destroys any possible symmetry, changing [0][0] of state to hard-coded constant
     */
    public void permutation(){
        for(int i = 0;i<24;i++){
            //theta
            long[] C=new long[5];
            long[] D=new long[5];
            for(int x=0;x<5;x++){
                C[x]=state[x][0]^state[x][1]^state[x][2]^state[x][3]^state[x][4];
            }
            for(int x=0;x<5;x++){
                D[x]=C[(x+4)%5]^Long.rotateLeft(C[(x+1)%5], 1);
            }
            for(int x = 0;x<5;x++){
                for(int y=0;y<5;y++){
                    state[x][y]^=D[x];
                }
            }
            //rho and pi
            long[][] temp=new long[5][5];
            for(int x=0;x<5;x++){
                for(int y=0;y<5;y++){
                    temp[y][(2*x+3*y)%5]=Long.rotateLeft(state[x][y], rotationOffset[x][y]);
                }
            }
            //chi
            for(int x =0;x<5;x++){
                for(int y=0;y<5;y++){
                    state[x][y]=temp[x][y]^((~temp[(x+1)%5][y])&temp[(x+2)%5][y]);
                }
            }
            //iota
            state[0][0]^=roundConstant[i];
        }

    }

    /**
     * Main workflow of program, doing padding, absorbing and permutation for all message blocks, also constructs output
     *
     * @param input message to be hashed
     *
     * @return output in bytes for printing in hex
     */
    public byte[] init(byte[] input){
        padding(input);
        for(byte[] message : messageBlocks){
            absorb(message);
            permutation();
        }
        byte[] output=new byte[32];
        int outputCnt=0;
        for(int lineIndex=0;outputCnt<output.length;lineIndex++){
            int x= lineIndex%5;
            int y = lineIndex/5;
            long line = state[x][y];
            for(int b=0;b<8;b++){
                output[outputCnt++]=(byte) ((line>>>(8*b))&0xFFL);
            }
        }
        return output;
    }

    /**
     * Main method, read data from file and hash it using my implementation of sha-3 and from library
     *
     * @param args didn't use here
     *
     * @throws Exception from Files, jvm will throw error if it occurs
     */
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        String filePath= sc.nextLine();
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] data = Files.readAllBytes(Paths.get(filePath));
        SHA3 sha=new SHA3();
        System.out.println("My implementation:");
        System.out.println(java.util.HexFormat.of().formatHex(sha.init(data)));
        System.out.println("Library implementation:");
        System.out.println(java.util.HexFormat.of().formatHex(digest.digest(data)));
    }
}