// ianbeer
package {
  import flash.utils.Proxy;
  import flash.utils.flash_proxy;
  
  public class MyProxy extends Proxy {
    private var first_time:Boolean

    public function MyProxy():void {
      first_time = true;
    }  

    override flash_proxy function getProperty(name:*):* {
      return 0x41414141;
    }

    override flash_proxy function hasProperty(name:*):Boolean {
      return true;
    }
    
    override flash_proxy function nextNameIndex(index:int):int {
      if (first_time) {
        if (index < 0x10) {
          return index + 1;
        }
        first_time = false;
        return 0;
      } else {
        if (index < 0x10000){
          return index + 1;
        }
        return 0;
      }
    }

    override flash_proxy function nextName(index:int):String {
      return String(index + 1);
    }
  }
}
