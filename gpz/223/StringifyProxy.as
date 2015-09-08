// ianbeer
package {
  import flash.display.Sprite;
  import flash.text.TextField;

  public class StringifyProxy extends Sprite {

    public function StringifyProxy() {
      var e:MyProxy = new MyProxy();
      JSON.stringify(e);

      var textField:TextField = new TextField();
      textField.text = "Hello, stringify!";
      addChild(textField);

      trace("Hello, world!");
    }
  }
}


