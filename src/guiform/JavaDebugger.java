/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package guiform;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import com.sun.jdi.*;
import com.sun.jdi.connect.AttachingConnector;
import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.IllegalConnectorArgumentsException;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
/**
 *
 * @author Trance
 */
public class JavaDebugger extends Thread {
        private List<ThreadReference> threads = null;
        List<ThreadGroupReference> threadGroups = null;
        private List<ReferenceType>  refTypes = null;
        private VirtualMachine vm = null; 
        private Hashtable methodsToWatch = null ; 
        private String connectionStr = null;
        private List<ReferenceType> allClassTypes = null;
        private List<Method> allMethodTypes = null;
        private LinkedList<String> callGraph = null ; 
        private boolean runFlag = true;
        private boolean vmDied;
        private String[] excludes = {"java.*", "javax.*", "sun.*", "com.sun.*", 
                                     "oracle.ewt.*", "oracle.forms.ui.*" };
        
        public  JavaDebugger(VirtualMachine jvm) throws IOException
        {
                //connectionStr = connStr;
                vm = jvm ; //connect(connStr);
                refTypes = new ArrayList<>();
                methodsToWatch = new Hashtable();
                allMethodTypes = new ArrayList<>();
                threadGroups = new ArrayList<>();
                threads = vm.allThreads();
                allClassTypes = vm.allClasses();
                for (ReferenceType tmpClass: allClassTypes) {
                    List<Method> methodsAll = tmpClass.allMethods();
                    for (Method tmpMeth : methodsAll) {
                        allMethodTypes.add(tmpMeth);
                    }
                }
                for(ThreadReference thr : threads) {
                 threadGroups.add(thr.threadGroup());
                }
                setEventRequests();
                callGraph = new LinkedList<String>();
        }
        public void disconnectFromVM() {
            //vm.resume();
            //vm = null;
            System.out.println("disconnected from VM!");
            runFlag = false;
        }
        public void addExclusionClass(String exclusion) {
            excludes[excludes.length] = exclusion;
        }
        public boolean canVMGenerateByteCode() {
            if (vm != null) 
                return vm.canGetBytecodes();
            return false;
        }
	/*private VirtualMachine connect(String args)
        throws IOException {
		String strPort = args.toString();
		AttachingConnector connector = getConnector();   
		System.err.println("Port received " + strPort + "\n");
		try {
			vm = connect(connector, strPort);
			return vm;
		} 
		catch (IllegalConnectorArgumentsException e) {
			throw new IllegalStateException(e);
		}
	}*/
        public List<ThreadReference> getThreadList() {  
             return threads;
        }
        
        public List<ReferenceType> getReferences() {
             refTypes = vm.allClasses();
             return refTypes;
        }
        public List<ThreadGroupReference> getThreadGroupsForVM() {
            return threadGroups;
        }
        public List<ThreadGroupReference> getTopLevelThreadGroups() {
            return vm.topLevelThreadGroups();
        }
        public String[] disassembleByteCode(byte[] inputBytes) {
            String[] byteCodeStr = new String[512]; 
            byte tmpByte[] = new byte[10];
            int intparm,intparm2;
            byte val;
            for (int i=0; i < inputBytes.length; i++) {
                val = (byte) (inputBytes[i] & 0x80);
                val += (byte) (inputBytes[i] & 0x7f);
                int testval = (int)val;
                switch(testval) {
                    case 0x32:
                        byteCodeStr[i] = "aaload";
                        break;
                    case 0x53:
                        byteCodeStr[i] = "aastore";
                        break;
                    case 0x01:
                        byteCodeStr[i] = "aconst_null";
                        break;
                    case 0x19:
                        byteCodeStr[i] = "aload";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        i+=1;
                        break;
                    case 0x2a:
                        byteCodeStr[i] = "aload_0";
                        break;
                    case 0x2b:
                        byteCodeStr[i] = "aload_1";
                        break;
                    case 0x2c:
                        byteCodeStr[i] = "aload_2";
                        break;
                    case 0x2d:
                        byteCodeStr[i] = "aload_3";
                        break;
                    case 0xbd:
                        byteCodeStr[i] = "anewarray";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                                //+tmpByte[2];
                        i+=2;
                        break;
                    case 0xb0:
                        byteCodeStr[i] = "areturn";
                        break;
                    case 0xbe:
                        byteCodeStr[i] = "arraylength";
                        break;
                    case 0x3a:
                        byteCodeStr[i] = "astore";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x4b:
                        byteCodeStr[i] = "astore_0";
                        break;
                    case 0x4c:
                        byteCodeStr[i] = "astore_1";
                        break;
                    case 0x4d:
                        byteCodeStr[i] = "astore_2";
                        break;
                    case 0x4e:
                        byteCodeStr[i] = "astore_3";
                        break;
                    case 0xbf:
                        byteCodeStr[i] = "athrow";
                        break;
                    case 0x33:
                        byteCodeStr[i] = "baload";
                        break;
                    case 0x54:
                        byteCodeStr[i] = "bastore";
                        break;
                    case 0x10:
                        byteCodeStr[i] = "bipush";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x34:
                        byteCodeStr[i] = "caload";
                        break;
                    case 0x55:
                        byteCodeStr[i] = "castore";
                        break;
                    case 0xc0:
                        byteCodeStr[i] = "checkcast";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x90:
                        byteCodeStr[i] = "d2f";
                        break;
                    case 0x8e:
                        byteCodeStr[i] = "d2i";
                        break;
                    case 0x8f:
                        byteCodeStr[i] = "d2l";
                        break;
                    case 0x63:
                        byteCodeStr[i] = "dadd";
                        break;
                    case 0x31:
                        byteCodeStr[i] = "daload";
                        break;
                    case 0x52:
                        byteCodeStr[i] = "dastore";
                        break;
                    case 0x98:
                        byteCodeStr[i] = "dcmpg";
                        break;
                    case 0x97:
                        byteCodeStr[i] = "dcmpl";
                        break;
                    case 0x0e:
                        byteCodeStr[i] = "dconst_0";
                        break;
                    case 0x0f:
                        byteCodeStr[i] = "dconst_1";
                        break;
                    case 0x6f:
                        byteCodeStr[i] = "ddiv";
                        break;
                    case 0x18:
                        byteCodeStr[i] = "dload";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x26:
                        byteCodeStr[i] = "dload_0";
                        break;
                    case 0x27:
                        byteCodeStr[i] = "dload_1";
                        break;
                    case 0x28:
                        byteCodeStr[i] = "dload_2";
                        break;
                    case 0x29:
                        byteCodeStr[i] = "dload_3";
                        break;
                    case 0x6b:
                        byteCodeStr[i] = "dmul";
                        break;
                    case 0x77:
                        byteCodeStr[i] = "dneg";
                        break;
                    case 0x73:
                        byteCodeStr[i] = "drem";
                        break;
                    case 0xaf:
                        byteCodeStr[i] = "dreturn";
                        break;
                    case 0x39:
                        byteCodeStr[i] = "dstore";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x47:
                        byteCodeStr[i] = "dstore_0";
                        break;
                    case 0x48:
                        byteCodeStr[i] = "dstore_1";
                        break;
                    case 0x49:
                        byteCodeStr[i] = "dstore_2";
                        break;
                    case 0x4a:
                        byteCodeStr[i] = "dstore_3";
                        break;
                    case 0x67:
                        byteCodeStr[i] = "dsub";
                        break;
                    case 0x59:
                        byteCodeStr[i] = "dup";
                        break;
                    case 0x5a:
                        byteCodeStr[i] = "dup_x1";
                        break;
                    case 0x5b:
                        byteCodeStr[i] = "dup_x2";
                        break;
                    case 0x5c:
                        byteCodeStr[i] = "dup2";
                        break;
                    case 0x5d:
                        byteCodeStr[i] = "dup2_x1";
                        break;
                    case 0x5e:
                        byteCodeStr[i] = "dup2_x2";
                        break;
                    case 0x8d:
                        byteCodeStr[i] = "f2d";
                        break;
                    case 0x8b:
                        byteCodeStr[i] = "f2i";
                        break;
                    case 0x8c:
                        byteCodeStr[i] = "f2l";
                        break;
                    case 0x62:
                        byteCodeStr[i] = "fadd";
                        break;
                    case 0x30:
                        byteCodeStr[i] = "faload";
                        break;
                    case 0x51:
                        byteCodeStr[i] = "fastore";
                        break;
                    case 0x96:
                        byteCodeStr[i] = "fcmpg";
                        break;
                    case 0x95:
                        byteCodeStr[i] = "fcmpl";
                        break;
                    case 0x0b:
                        byteCodeStr[i] = "fconst_0";
                        break;
                    case 0x0c:
                        byteCodeStr[i] = "fconst_1";
                        break;
                    case 0x0d:
                        byteCodeStr[i] = "fconst_2";
                        break;
                    case 0x6e:
                        byteCodeStr[i] = "fdiv";
                        break;
                    case 0x17:
                        byteCodeStr[i] = "fload";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x22:
                        byteCodeStr[i] = "fload_0";
                        break;
                    case 0x23:
                        byteCodeStr[i] = "fload_1";
                        break;
                    case 0x24:
                        byteCodeStr[i] = "fload_2";
                        break;
                    case 0x25:
                        byteCodeStr[i] = "fload_3";
                        break;
                    case 0x6a:
                        byteCodeStr[i] = "fmul";
                        break;
                    case 0x76:
                        byteCodeStr[i] = "fneg";
                        break;
                    case 0x72:
                        byteCodeStr[i] = "frem";
                        break;
                    case 0xae:
                        byteCodeStr[i] = "freturn";
                        break;
                    case 0x38:
                        byteCodeStr[i] = "fstore";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x43:
                        byteCodeStr[i] = "fstore_0";
                        break;
                    case 0x44:
                        byteCodeStr[i] = "fstore_1";
                        break;
                    case 0x45:
                        byteCodeStr[i] = "fstore_2";
                        break;
                    case 0x46:
                        byteCodeStr[i] = "fstore_3";
                        break;
                    case 0x66:
                        byteCodeStr[i] = "fsub";
                        break;
                    case 0xb4:
                        byteCodeStr[i] = "getfield";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xb2:
                        byteCodeStr[i] = "getstatic";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa7:
                        byteCodeStr[i] = "goto";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xc8:
                        byteCodeStr[i] = "goto_w";
                        intparm = inputBytes[i+1] << 24 | inputBytes[i+2] << 16 |
                                inputBytes[i+3] << 8 | inputBytes[i+4];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=4;
                        break;
                    case 0x91:
                        byteCodeStr[i] = "i2b";
                        break;
                    case 0x92:
                        byteCodeStr[i] = "i2c";
                        break;
                    case 0x87:
                        byteCodeStr[i] = "i2d";
                        break;
                    case 0x86:
                        byteCodeStr[i] = "i2f";
                        break;
                    case 0x85:
                        byteCodeStr[i] = "i2l";
                        break;
                    case 0x93:
                        byteCodeStr[i] = "i2s";
                        break;
                    case 0x60:
                        byteCodeStr[i] = "iadd";
                        break;
                    case 0x2e:
                        byteCodeStr[i] = "iaload";
                        break;
                    case 0x7e:
                        byteCodeStr[i] = "iand";
                        break;
                    case 0x4f:
                        byteCodeStr[i] = "iastore";
                        break;
                    case 0x02:
                        byteCodeStr[i] = "iconst_m1";
                        break;
                    case 0x03:
                        byteCodeStr[i] = "iconst_0";
                        break;
                    case 0x04:
                        byteCodeStr[i] = "iconst_1";
                        break;
                    case 0x05:
                        byteCodeStr[i] = "iconst_2";
                        break;
                    case 0x06:
                        byteCodeStr[i] = "iconst_3";
                        break;
                    case 0x07:
                        byteCodeStr[i] = "iconst_4";
                        break;
                    case 0x08:
                        byteCodeStr[i] = "iconst_5";
                        break;
                    case 0x6c:
                        byteCodeStr[i] = "idiv";
                        break;
                    case 0xa5:
                        byteCodeStr[i] = "if_acmpeq";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa6:
                        byteCodeStr[i] = "if_acmpne";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x9f:
                        byteCodeStr[i] = "if_icmpeq";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa0:
                        byteCodeStr[i] = "if_icmpne";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa1:
                        byteCodeStr[i] = "if_icmplt";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa2:
                        byteCodeStr[i] = "if_icmpge";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa3:
                        byteCodeStr[i] = "if_icmpgt";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa4:
                        byteCodeStr[i] = "if_icmple";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x99:
                        byteCodeStr[i] = "ifeq";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x9a:
                        byteCodeStr[i] = "ifne";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x9b:
                        byteCodeStr[i] = "iflt";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x9c:
                        byteCodeStr[i] = "ifge";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x9d:
                        byteCodeStr[i] = "ifgt";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x9e:
                        byteCodeStr[i] = "ifle";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        byteCodeStr[i] += " "+tmpByte[0]+" ,"+tmpByte[1];
                        i+=2;
                        break;
                    case 0xc7:
                        byteCodeStr[i] = "ifnonnull";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        byteCodeStr[i] += " "+tmpByte[0]+" ,"+tmpByte[1];
                        i+=2;
                        break;
                    case 0xc6:
                        byteCodeStr[i] = "ifnull";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x84:
                        byteCodeStr[i] = "iinc";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        tmpByte[1] = (byte) (inputBytes[i+2] & 0x80);
                        tmpByte[1] += (byte) (inputBytes[i+2] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0]+" ,"+tmpByte[1];
                        i+=2;
                        break;
                    case 0x15:
                        byteCodeStr[i] = "iload";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x1a:
                        byteCodeStr[i] = "iload_0";
                        break;
                    case 0x1b:
                        byteCodeStr[i] = "iload_1";
                        break;
                    case 0x1c:
                        byteCodeStr[i] = "iload_2";
                        break;
                    case 0x1d:
                        byteCodeStr[i] = "iload_3";
                        break;
                    case 0x68:
                        byteCodeStr[i] = "imul";
                        break;
                    case 0x74:
                        byteCodeStr[i] = "ineg";
                        break;
                    case 0xc1:
                        byteCodeStr[i] = "instanceof";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xba:
                        byteCodeStr[i] = "invokedynamic";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        intparm = inputBytes[i+3] << 8 | inputBytes[i+4];
                        byteCodeStr[i] += ", "+intparm;//+", "
                        i+=4;
                        break;
                    case 0xb9:
                        byteCodeStr[i] = "invokeinterface";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        tmpByte[0] = (byte) (inputBytes[i+3] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+3] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];//+", "
                        
                        tmpByte[1] = (byte) (inputBytes[i+4] & 0x80);
                        tmpByte[1] += (byte) (inputBytes[i+4] & 0x7f);
                        byteCodeStr[i] += ", "+tmpByte[1];//+", "
                        i+=4;
                        break;
                    case 0xb7:
                        byteCodeStr[i] = "invokespecial";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xb8:
                        byteCodeStr[i] = "invokestatic";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xb6:
                        byteCodeStr[i] = "invokevirtual";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x80:
                        byteCodeStr[i] = "ior";
                        break;
                    case 0x70:
                        byteCodeStr[i] = "irem";
                        break;
                    case 0xac:
                        byteCodeStr[i] = "ireturn";
                        break;
                    case 0x78:
                        byteCodeStr[i] = "ishl";
                        break;
                    case 0x7a:
                        byteCodeStr[i] = "ishr";
                        break;
                    case 0x36:
                        byteCodeStr[i] = "istore";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x3b:
                        byteCodeStr[i] = "istore_0";
                        break;
                    case 0x3c:
                        byteCodeStr[i] = "istore_1";
                        break;
                    case 0x3d:
                        byteCodeStr[i] = "istore_2";
                        break;
                    case 0x3e:
                        byteCodeStr[i] = "istore_3";
                        break;
                    case 0x64:
                        byteCodeStr[i] = "isub";
                        break;
                    case 0x7c:
                        byteCodeStr[i] = "iushr";
                        break;
                    case 0x82:
                        byteCodeStr[i] = "ixor";
                        break;
                    case 0xa8:
                        byteCodeStr[i] = "jsr";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=1;
                        break;
                    case 0xc9:
                        byteCodeStr[i] = "jsr_w";
                        intparm = inputBytes[i+1] << 24 | inputBytes[i+2] << 16 |
                                inputBytes[i+3] << 8 | inputBytes[i+4];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=4;
                        break;
                    case 0x8a:
                        byteCodeStr[i] = "l2d";
                        break;
                    case 0x89:
                        byteCodeStr[i] = "l2f";
                        break;
                    case 0x88:
                        byteCodeStr[i] = "l2i";
                        break;
                    case 0x61:
                        byteCodeStr[i] = "ladd";
                        break;
                    case 0x2f:
                        byteCodeStr[i] = "laload";
                        break;
                    case 0x7f:
                        byteCodeStr[i] = "land";
                        break;
                    case 0x50:
                        byteCodeStr[i] = "lastore";
                        break;
                    case 0x94:
                        byteCodeStr[i] = "lcmp";
                        break;
                    case 0x09:
                        byteCodeStr[i] = "lconst_0";
                        break;
                    case 0x0a:
                        byteCodeStr[i] = "lconst_1";
                        break;
                    case 0x12:
                        byteCodeStr[i] = "ldc";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x13:
                        byteCodeStr[i] = "ldc_w";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x14:
                        byteCodeStr[i] = "ldc2_w";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x6d:
                        byteCodeStr[i] = "ldiv";
                        break;
                    case 0x16:
                        byteCodeStr[i] = "lload";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x1e:
                        byteCodeStr[i] = "lload_0";
                        break;
                    case 0x1f:
                        byteCodeStr[i] = "lload_1";
                        break;
                    case 0x20:
                        byteCodeStr[i] = "lload_2";
                        break;
                    case 0x21:
                        byteCodeStr[i] = "lload_3";
                        break;
                    case 0x69:
                        byteCodeStr[i] = "lmul";
                        break;
                    case 0x75:
                        byteCodeStr[i] = "lneg";
                        break;
                    case 0xab:
                        byteCodeStr[i] = "lookupswitch";
                        while (i%4 !=0)
                            i++;
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        intparm2 = inputBytes[i+3] << 8 | inputBytes[i+4];
                        i+=4;
                        for (int j=0; j<intparm; j++)
                        {    
                            //byteCodeStr[i] += " "+intparm;//+", "
                            i+=4;
                        }
                        byteCodeStr[i] += " lookupswitch "+intparm+" parameters";
                        break;
                    case 0x81:
                        byteCodeStr[i] = "lor";
                        break;
                    case 0x71:
                        byteCodeStr[i] = "lrem";
                        break;
                    case 0xad:
                        byteCodeStr[i] = "lreturn";
                        break;
                    case 0x79:
                        byteCodeStr[i] = "lshl";
                        break;
                    case 0x7b:
                        byteCodeStr[i] = "lshr";
                        break;
                    case 0x37:
                        byteCodeStr[i] = "lstore";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x3f:
                        byteCodeStr[i] = "lstore_0";
                        break;
                    case 0x40:
                        byteCodeStr[i] = "lstore_1";
                        break;
                    case 0x41:
                        byteCodeStr[i] = "lstore_2";
                        break;
                    case 0x42:
                        byteCodeStr[i] = "lstore_3";
                        break;
                    case 0x65:
                        byteCodeStr[i] = "lsub";
                        break;
                    case 0x7d:
                        byteCodeStr[i] = "lushr";
                        break;
                    case 0x83:
                        byteCodeStr[i] = "lxor";
                        break;
                    case 0xc2:
                        byteCodeStr[i] = "monitorenter";
                        break;
                    case 0xc3:
                        byteCodeStr[i] = "monitorexit";
                        break;
                    case 0xc5:
                        byteCodeStr[i] = "multianewarray";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        tmpByte[0] = (byte) (inputBytes[i+3] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+3] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=3;
                        
                        break;
                    case 0xbb:
                        byteCodeStr[i] = "new";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xbc:
                        byteCodeStr[i] = "newarray";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0x00:
                        byteCodeStr[i] = "nop";
                        break;
                    case 0x57:
                        byteCodeStr[i] = "pop";
                        break;
                    case 0x58:
                        byteCodeStr[i] = "pop2";
                        break;
                    case 0xb5:
                        byteCodeStr[i] = "putfield";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xb3:
                        byteCodeStr[i] = "putstatic";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0xa9:
                        byteCodeStr[i] = "ret";
                        tmpByte[0] = (byte) (inputBytes[i+1] & 0x80);
                        tmpByte[0] += (byte) (inputBytes[i+1] & 0x7f);
                        byteCodeStr[i] += " "+tmpByte[0];
                        i+=1;
                        break;
                    case 0xb1:
                        byteCodeStr[i] = "return";
                        break;
                    case 0x35:
                        byteCodeStr[i] = "saload";
                        break;
                    case 0x56:
                        byteCodeStr[i] = "sastore";
                        break;
                    case 0x11:
                        byteCodeStr[i] = "sipush";
                        intparm = inputBytes[i+1] << 8 | inputBytes[i+2];
                        byteCodeStr[i] += " "+intparm;//+", "
                        i+=2;
                        break;
                    case 0x5f:
                        byteCodeStr[i] = "swap";
                        break;
                    case 0xaa:
                        byteCodeStr[i] = "tableswitch";
                        while (i%4 !=0)
                            i++;
                        intparm = inputBytes[i+1] << 24 | inputBytes[i+2] << 16 |
                                inputBytes[i+3] << 8 | inputBytes[i+4];
                        byteCodeStr[i] += " "+intparm;
                        
                        intparm2 = inputBytes[i+5] << 24 | inputBytes[i+6] << 16 |
                                inputBytes[i+7] << 8 | inputBytes[i+8];
                        byteCodeStr[i] += ", "+intparm2;//+", "
                        int intparm3 = inputBytes[i+9] << 24 | inputBytes[i+10] << 16 |
                                inputBytes[i+11] << 8 | inputBytes[i+12];
                        byteCodeStr[i] += " " +intparm3;
                        i+=12;
                        for (int j=0; j<intparm3-intparm2; j++)
                        {    
                            //byteCodeStr[i] += " "+intparm;//+", "
                            i+=4;
                        }
                        //byteCodeStr[i] += " lookupswitch "+intparm+" parameters";
                        break;
                    case 0xc4:
                        byteCodeStr[i] = "wide";
                        break;
                    case 0xca:
                        byteCodeStr[i] = "breakpoint";
                        break;
                    case 0xfe:
                        byteCodeStr[i] = "impdep1";
                        break;
                    case 0xff:
                        byteCodeStr[i] = "impdep2";
                        break;
                    default:
                        break;
                }
            }
            return byteCodeStr;
        }
        public void setEventRequests () {
            EventRequestManager mgr = vm.eventRequestManager();
            MethodEntryRequest menr = mgr.createMethodEntryRequest(); // report method entries
            for (int i = 0; i < excludes.length; ++i) {
                menr.addClassExclusionFilter(excludes[i]);
            }
            menr.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
            menr.enable();

            MethodExitRequest mexr = mgr.createMethodExitRequest();   // report method exits
            for (int i = 0; i < excludes.length; ++i) {
                mexr.addClassExclusionFilter(excludes[i]);
            }
            mexr.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
            mexr.enable();

            ClassPrepareRequest cpr = mgr.createClassPrepareRequest(); // report class loads
            for (int i = 0; i < excludes.length; ++i) {
                cpr.addClassExclusionFilter(excludes[i]);
            }
            // cpr.setSuspendPolicy(EventRequest.SUSPEND_ALL);
            cpr.enable();

            ClassUnloadRequest cur = mgr.createClassUnloadRequest();  // report class unloads
            for (int i = 0; i < excludes.length; ++i) {
                cur.addClassExclusionFilter(excludes[i]);
            }
            // cur.setSuspendPolicy(EventRequest.SUSPEND_ALL);
            cur.enable();

            ThreadStartRequest tsr = mgr.createThreadStartRequest();  // report thread starts
            tsr.enable();

            ThreadDeathRequest tdr = mgr.createThreadDeathRequest();  // report thread deaths
            tdr.enable();
        }
	public String addMethodWatch(Method m) {
            methodsToWatch.put(m.declaringType().name()+'.'+m.name(),1);
            //EventRequestManager erm = vm.eventRequestManager();
            //MethodEntryRequest mer = erm.createMethodEntryRequest();
            //if (!mer.isEnabled()) 
            //    mer.enable();
            //erm.deleteAllBreakpoints();
            System.err.println("Watch added on Method "+m.toString());
            System.err.println("Current Watches == >");
            Enumeration methods ; 
            methods = methodsToWatch.keys();
            while (methods.hasMoreElements()) {
                System.err.println((String)methods.nextElement());
            }
            return m.toString();
            
            /*ModificationWatchpointRequest modificationWatchpointRequest = erm
                .createModificationWatchpointRequest(field);
            modificationWatchpointRequest.setEnabled(true);*/
        }
        private AttachingConnector getConnector() {
		VirtualMachineManager vmManager = Bootstrap.virtualMachineManager();
                
		for (Connector connector : vmManager.attachingConnectors()) {
			System.err.println(connector.name());
			if ("com.sun.jdi.SocketAttach".equals(connector.name())) {
				return (AttachingConnector) connector;
			}
		}
		throw new IllegalStateException();
	}
        private void methodEntryEvent (MethodEntryEvent event) {
            Method meth = event.method();
            String className = meth.declaringType().name();
            
            System.out.println();
            if (meth.isConstructor()) {
                System.out.println("entered " + className + " constructor");
                callGraph.add("[+] "+className+"()");
                try {
                    printFields(event.thread().frame(0).thisObject());
                }
                catch(IncompatibleThreadStateException itse) {
                    System.err.println(itse.getMessage());
                    //return;
                }
                catch (NullPointerException npe) {
                    //return;
                }
               
            }
            else {
                System.out.println("entered " + className +  "." + meth.name() +"()");
                callGraph.add("[+] "+className+"."+meth.name()+"()");
            }
        }
        
        private void methodExitEvent (MethodExitEvent event) {
            Method meth = event.method();
            
            String className = meth.declaringType().name();
            boolean dontprocess = false; 
            
            for (int i=0; i < excludes.length; i++)  {
                Pattern p = Pattern.compile(excludes[i]);
                Matcher m  = p.matcher(className);
                if (m.matches())
                    dontprocess = true;
            }
            System.out.println();
            if (meth.isConstructor() && !dontprocess) {
                System.out.println("exited " + className + " constructor");
                callGraph.add("[-] "+className+"()");
                try {
                    printFields(event.thread().frame(0).thisObject());
                }
                catch(IncompatibleThreadStateException itse) {
                    System.err.println(itse.getMessage());
                    //return;
                }
                catch (NullPointerException npe) {
                    //return;
                }   
            }
            else
                if (!dontprocess) {
                    callGraph.add("[-] "+className+"."+meth.name()+"()");
                    System.out.println("exited " + className +  "." + meth.name() +"()");
                    try {
                        printFields(event.thread().frame(0).thisObject());
                    }
                    catch (IncompatibleThreadStateException itse) { 
                        System.err.println(itse.getMessage());
                    }
                }
        }
        
	private VirtualMachine connect(AttachingConnector connector, String port)
                        throws IllegalConnectorArgumentsException,
                        IOException {
            Map<String, Connector.Argument> args = connector.defaultArguments();
            Connector.Argument pidArgument = args.get("port");
            if (pidArgument == null) {
                throw new IllegalStateException();
            }
            pidArgument.setValue(port);
            Connector.Argument targetSystem = args.get("hostname");
            targetSystem.setValue("localhost");
            System.err.println(args.toString());
            return connector.attach(args);
	}
        @Override
        public void run() {
            EventQueue eventQueue = vm.eventQueue();
            while (runFlag) {
                try {
                    EventSet eventSet = eventQueue.remove();
                    for (Event event : eventSet) {
                        handleEvent(event);
                    }
                    eventSet.resume();
                }
                catch (InterruptedException ie) {
                    System.err.println(ie.getMessage());
                }
                catch (VMDisconnectedException discExc) {
                    handleDisconnectedException();
                }
            }
        }
        
        private void handleEvent(Event event) {
            if (event instanceof VMDeathEvent) {
                vmDeathEvent((VMDeathEvent) event);
            }
            else if (event instanceof VMDisconnectEvent) {
                vmDisconnectEvent((VMDisconnectEvent) event);
            }
            else if (event instanceof ClassPrepareEvent) {
                    //vm.resume();
            }
            else if (event instanceof ModificationWatchpointEvent) {  }
            else if (event instanceof MethodEntryEvent) {
                if (methodsToWatch.isEmpty())
                    methodEntryEvent((MethodEntryEvent) event);
                else 
                    methodEntryEvent2((MethodEntryEvent) event);
            }
            else if (event instanceof MethodExitEvent) { 
                if (methodsToWatch.isEmpty()) 
                    methodExitEvent((MethodExitEvent)event);
                else methodExitEvent2((MethodExitEvent)event);
            }
            else if (event instanceof ClassPrepareEvent) {
                classPrepareEvent((ClassPrepareEvent) event);
            } else if (event instanceof ClassUnloadEvent) {
                classUnloadEvent((ClassUnloadEvent) event);
            } // thread events
            else if (event instanceof ThreadStartEvent) {
                threadStartEvent((ThreadStartEvent) event);
            } else if (event instanceof ThreadDeathEvent) {
                threadDeathEvent((ThreadDeathEvent) event);
            } // step event -- a line of code is about to be executed
            else if (event instanceof StepEvent) {
                stepEvent((StepEvent) event);
            } // modified field event  -- a field is about to be changed
            else if (event instanceof ModificationWatchpointEvent) {
                fieldWatchEvent((ModificationWatchpointEvent) event);
            } // VM events
            else if (event instanceof VMStartEvent) {
                vmStartEvent((VMStartEvent) event);
            } else if (event instanceof VMDeathEvent) {
                vmDeathEvent((VMDeathEvent) event);
            } else if (event instanceof VMDisconnectEvent) {
                vmDisconnectEvent((VMDisconnectEvent) event);
            } else if (event instanceof AccessWatchpointEvent) { 
                accessWatchEvent((AccessWatchpointEvent)event);
            } else {
                //System.err.println(event.toString());
                //throw new Error("Unexpected event type");
                return;
            }
        }
        
        private void accessWatchEvent(AccessWatchpointEvent event) {
            AccessWatchpointEvent awe = (AccessWatchpointEvent) event;
            //List<Field> fieldToWatch = new ArrayList<>();
            //fieldToWatch.add(event.field());
            //setAccessWatch(fieldToWatch);
            System.err.println("Field value for "+awe.object().getClass().toString()+awe.field()
                    +" = "+awe.valueCurrent().toString());
            //return obj;
        }
        private void methodExitEvent2(MethodExitEvent event) {
            MethodExitEvent metEvent = (MethodExitEvent) event;
            Method tmpMethod = metEvent.method();
            if (methodsToWatch.containsKey(tmpMethod.declaringType().name()+'.'+tmpMethod.name())) {
                callGraph.add("[-] "+tmpMethod.declaringType().name());
            //        System.err.println(tmpMethod.declaringType().name()+"."+tmpMethod.name()+" @ "+
            //                tmpMethod.location().lineNumber());
                try {
                    ThreadReference threadRef4Method = metEvent.thread();
                    System.err.println("[*] Number of frames for " + tmpMethod.declaringType().name()+
                            '.'+tmpMethod.name()+" = "  
                            +  threadRef4Method.frameCount());
                    printLocals(threadRef4Method.frame(0));
                    printFields(threadRef4Method.frame(0).thisObject());
                    printInitialState(threadRef4Method);
                }
                catch (IncompatibleThreadStateException itse) { //| AbsentInformationException itse) {
                    System.err.println(itse.getMessage());
                }
            }
        }
        private void methodEntryEvent2(MethodEntryEvent event) {
            MethodEntryEvent metEvent = (MethodEntryEvent) event;
            Method tmpMethod = metEvent.method();
            
            //String className = tmpMethod.declaringType().name();
            //boolean dontprocess = false; 
            /*
            for (int i=0; i < excludes.length; i++)  {
                Pattern p = Pattern.compile(excludes[i]);
                Matcher m  = p.matcher(className);
                if (m.matches())
                    dontprocess = true;
            }*/
            if (methodsToWatch.containsKey(tmpMethod.declaringType().name()+'.'+tmpMethod.name())) {
                    callGraph.add("[+] " + tmpMethod.declaringType().name());
                    
                    System.err.println(tmpMethod.declaringType().name()+"."+tmpMethod.name()+" @ "+
                            tmpMethod.location().lineNumber());        
                    try {
                        ThreadReference threadRef4Method = metEvent.thread();
                        System.err.println("[*] Number of frames for " + tmpMethod.name() 
                              +" = "  +  threadRef4Method.frameCount());
                        /*for (int i = 0; i < threadRef4Method.frameCount(); i++)
                        { 
                            System.err.println("Frame : "+i+ "==>"+
                            threadRef4Method.frame(i).location().toString()); 
                        }*/
                        if (threadRef4Method!=null) {
                            if (threadRef4Method.frame(0) != null)
                            {    
                                printLocals(threadRef4Method.frame(0));
                                if (threadRef4Method.frame(0).thisObject() != null)
                                    printFields(threadRef4Method.frame(0).thisObject());
                                //printInitialState(threadRef4Method);
                            }//if (tmpMethod.arguments().size() > 0) {
                        //}
                        }
                    }
                    catch (IncompatibleThreadStateException itse) { //| AbsentInformationException itse) {
                        System.err.println(itse.getMessage());
                    }
             }
        }
        private synchronized void handleDisconnectedException()
        {
            EventQueue queue = vm.eventQueue();
            while (runFlag) {
                try {
                    EventSet eventSet = queue.remove();
                    for(Event event : eventSet) {
                        if (event instanceof VMDeathEvent)
                            vmDeathEvent((VMDeathEvent) event);
                        else 
                            if (event instanceof VMDisconnectEvent)
                                vmDisconnectEvent((VMDisconnectEvent) event);
                    }
                    eventSet.resume(); // resume the VM
                }
                catch (InterruptedException e) { }  // ignore
            }
        }  // end of handleDisconnectedException()
        private void vmStartEvent(VMStartEvent event)
        /* Notification of initialization of a target VM. This event is received 
            before the main thread is started and before any application code has 
            been executed. */
        { 
            vmDied = false;
            System.out.println("-- VM Started --"); 
        }
        private void vmDeathEvent(VMDeathEvent event)
        // Notification of VM termination
        { 
            vmDied = true;
            System.out.println("-- The application has exited --");
        }
        private void vmDisconnectEvent(VMDisconnectEvent event)
        /* Notification of disconnection from the VM, either through normal termination 
            or because of an exception/error. */
        { 
            runFlag = false;
            if (!vmDied)
            System.out.println("-- The application has been disconnected --");
        }
        private void classPrepareEvent(ClassPrepareEvent event) {
            ReferenceType ref = event.referenceType();

            List<Field> fields = ref.fields();
            List<Method> methods = ref.methods();

            String fnm;
            try {
                fnm = ref.sourceName();  // get filename of the class
                //showCode.add(fnm);
                System.err.println(fnm);
            } catch (AbsentInformationException e) {
                fnm = "??";
            }

            System.out.println("loaded class: " + ref.name() + " from " + fnm
                    + " - fields=" + fields.size() + ", methods=" + methods.size());

            System.out.println("  method names: ");
            for (Method m : methods) {
                System.out.println("    | " + m.name() + "()");
            }
            setFieldsWatch(fields);
        }
        private void classUnloadEvent(ClassUnloadEvent event) { 
            if (!vmDied)
                System.err.println("unloaded class: " + event.className());  
        }
        public void setAccessWatch(List<Field> fields) {
            EventRequestManager mgr = vm.eventRequestManager();
            for (Field field : fields) {
                AccessWatchpointRequest req =
                        mgr.createAccessWatchpointRequest(field);
                for (int i = 0; i < excludes.length; i++) {
                    req.addClassExclusionFilter(excludes[i]);
             }
             req.setSuspendPolicy(EventRequest.SUSPEND_NONE);
             req.enable();
            }
        }
        public void setFieldsWatch(List<Field> fields) {
            EventRequestManager mgr = vm.eventRequestManager();

            for (Field field : fields) {
                ModificationWatchpointRequest req =
                        mgr.createModificationWatchpointRequest(field);
                for (int i = 0; i < excludes.length; i++) {
                    req.addClassExclusionFilter(excludes[i]);
                }
                req.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                req.enable();
            }
        }
        private void stepEvent(StepEvent event) {
            Location loc = event.location();
            try {   // print the line
                String fnm = loc.sourceName();  // get filename of code
                System.out.println(fnm + ": " + fnm + loc.lineNumber());
            } catch (AbsentInformationException e) { }
            if (loc.codeIndex() == 0) // at the start of a method
            {
                printInitialState(event.thread());
            }
        }
        private void threadDeathEvent (ThreadDeathEvent event) {
            ThreadReference thr = event.thread();
            if (thr.name().equals("DestroyJavaVM")
                    || thr.name().startsWith("AWT-"))
                return;
            if (thr.threadGroup()!= null && 
                    thr.threadGroup().name().equals("system")) // ignore system threads
                return;
            System.out.println(thr.name() + " thread about to die");
        }
        private void threadStartEvent(ThreadStartEvent event) {
            ThreadReference thr = event.thread();

            if (thr.name().equals("Signal Dispatcher")
                    || thr.name().equals("DestroyJavaVM")
                    || thr.name().startsWith("AWT-")) // AWT threads
            {
                return;
            }

            if (thr.threadGroup().name().equals("system")) // ignore system threads
            {
                return;
            }

            System.out.println(thr.name() + " thread started");

            setStepping(thr);
        }
        private void setStepping(ThreadReference thr) // start single stepping through the new thread
        {
            EventRequestManager mgr = vm.eventRequestManager();
            StepRequest sr = mgr.createStepRequest(thr, StepRequest.STEP_LINE,
                    StepRequest.STEP_INTO);
            sr.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
            for (int i = 0; i < excludes.length; ++i) {
                sr.addClassExclusionFilter(excludes[i]);
            }
            sr.enable();
        }  // end of setStepping()

        private void fieldWatchEvent(ModificationWatchpointEvent event) {
            Field f = event.field();
            Value value = event.valueToBe();   // value that _will_ be assigned
            System.out.println("    > " + f.name() + " = " + value);
        }
        private void printInitialState(ThreadReference thr) {
        // get top-most current stack frame
            StackFrame currFrame = null;
            try {
                currFrame = thr.frame(0);
            } catch (Exception e) {
                return;
            }

            printLocals(currFrame);

            // print fields info for the 'this' object
            ObjectReference objRef = currFrame.thisObject();   // get 'this' object
            if (objRef != null) {
                System.out.println("  object: " + objRef.toString());
                printFields(objRef);
            }
    }  // end of printInitialState()

    private void printLocals(StackFrame currFrame) {
        List<LocalVariable> locals = null;
        List<Value> values = null;
        Map<LocalVariable,Value> argValues = null;
        
        //try {
            //locals = currFrame.visibleVariables();
        values = currFrame.getArgumentValues();
        //} catch (AbsentInformationException e) {
        //    e.printStackTrace();
        //    System.err.println("[-] Error in getting locals!");
        //    return;
        //}
        if (values.isEmpty())
        //if (locals.isEmpty())
            return;
        System.out.println("  locals: ");
        
        //Set set = argValues.entrySet();
        // Get an iterator
        //Iterator i = set.iterator();
        // Display elements
        //while (i.hasNext()) {
        //    Map.Entry me = (Map.Entry) i.next();
        for (Value i : values) {
            if (i!=null && i.type() != null ) {
                System.out.print("     | "+ i.type().name() + " = ");
                if (i instanceof StringReference) {
                    System.out.println(((StringReference)i).value());
                }
                else
                    System.out.println(i.toString());
            }    
        }
        /*for (LocalVariable l : locals) {
            System.out.println("    | " + l.name()
                    + " = " + currFrame.getValue(l));
        }*/
    }  // end of printLocals()

    private void printFields(ObjectReference objRef) {
        if (objRef == null) {
            System.err.println("Null Object Reference to printFields\n");
            return;
        }
        ReferenceType ref = objRef.referenceType();  // get type (class) of object
        List<Field> fields = null;
        try {
            fields = ref.allFields();
            //fields = ref.fields();      // only this object's fields
            // could use allFields() to include inherited fields
        } catch (ClassNotPreparedException e) {
            return;
        }
        System.out.println("  fields: ");
        if (fields != null)
        {
            for (Field f : fields) {
                if (objRef.getValue(f) != null &&
                        objRef.getValue(f).type() instanceof ArrayType) {
                    ArrayReference arrRef = ((ArrayReference)objRef.getValue(f));
                    System.out.println("    | " + f.name() + " = ");
                    StringBuffer sb = new StringBuffer();
                    for (int i = 0; i < arrRef.length(); i++) {
                        if (arrRef.getValue(i) != null) {
                            if (arrRef.getValue(i).type() instanceof ByteType)
                                //System.out.print((((ByteValue)arrRef.getValue(i)).byteValue()));
                            {    
                                byte test = ((ByteValue)arrRef.getValue(i)).byteValue();
                                sb.append((char) (test & 0xff));
                            }
                            else if (arrRef.getValue(i).type() instanceof CharType)
                                //System.out.print(((CharValue)arrRef.getValue(i)).charValue());
                                sb.append(((CharValue)arrRef.getValue(i)).charValue());
                            else if (arrRef.getValue(i).type() instanceof IntegerType)
                                System.out.print(((IntegerValue)arrRef.getValue(i)).intValue());
                            else if (arrRef.getValue(i).type() instanceof ShortType)
                                System.out.print(((ShortValue)arrRef.getValue(i)).shortValue()); 
                            else if (arrRef.getValue(i).type() instanceof StringReference) 
                                System.out.print(arrRef.getValue(i));
                        }
                    }
                    System.out.println("    | " + f.name() + "[] = "+sb.toString());
                    hexdump(sb);
                }
                else if (objRef.getValue(f)!=null && objRef.getValue(f).type() instanceof ClassType) 
                    System.out.println("    | " + f.name() + " = " + f.genericSignature());
                else System.out.println("    | " + f.name() + " = " + objRef.getValue(f));
            }
        }
    }  // end of printFields()
    public boolean addBreakpoint(Method m) {
        
        return false;
    }
    private void hexdump(StringBuffer sb) {
        System.out.println("Hexdump: ");
        
        for (int i=0; i < sb.length(); i++) {
            if (i%16 == 0) 
            {    
                System.out.println();
                System.out.print('\t');
            }
            System.out.print("0x"+Integer.toHexString((int)sb.charAt(i))+" ");
            
        }
    }
}
