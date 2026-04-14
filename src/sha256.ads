with System.Storage_Elements;
with Interfaces;

package SHA256 is

   pragma Pure;
   pragma SPARK_Mode;
   pragma Unevaluated_Use_Of_Old (Allow);

   use type System.Storage_Elements.Storage_Offset;
   use type Interfaces.Unsigned_64;

   Digest_Length : constant System.Storage_Elements.Storage_Offset := 32;
   Block_Length  : constant System.Storage_Elements.Storage_Offset := 64;

   Max_Data_Length : constant System.Storage_Elements.Storage_Offset :=
     System.Storage_Elements.Storage_Offset'Last / 2;

   Max_Message_Bytes : constant Interfaces.Unsigned_64 :=
     Interfaces.Unsigned_64 (2**61 - 1);

   subtype Digest is System.Storage_Elements.Storage_Array (1 .. Digest_Length);

   type Context is private;

   function Is_Initialized (Ctx : Context) return Boolean
     with Ghost;

   function Message_Byte_Count (Ctx : Context)
     return Interfaces.Unsigned_64
     with Ghost;

   procedure Initialize (Ctx : out Context)
     with Post => Is_Initialized (Ctx)
                 and then Message_Byte_Count (Ctx) = 0;

   procedure Update (Ctx  : in out Context;
                     Data : System.Storage_Elements.Storage_Array)
     with Pre  => Is_Initialized (Ctx)
                 and then Data'First >= 0
                 and then Data'Last <= Max_Data_Length
                 and then Interfaces.Unsigned_64 (Data'Length) <=
                   Max_Message_Bytes
                 and then Message_Byte_Count (Ctx) <= Max_Message_Bytes
                              - Interfaces.Unsigned_64 (Data'Length),
          Post => Is_Initialized (Ctx)
                 and then Message_Byte_Count (Ctx) <= Max_Message_Bytes
                 and then Message_Byte_Count (Ctx) =
                   Message_Byte_Count (Ctx)'Old
                     + Interfaces.Unsigned_64 (Data'Length);

   procedure Finalize (Ctx    : in out Context;
                       Output : out Digest)
     with Pre  => Is_Initialized (Ctx),
          Post => not Is_Initialized (Ctx)
                  and then Message_Byte_Count (Ctx) = 0;

private

   pragma SPARK_Mode;

   subtype Word is Interfaces.Unsigned_32;

   type State_Array is array (Natural range 0 .. 7) of Word;
   type Byte_Block is array (Natural range 0 .. 63) of Interfaces.Unsigned_8;
   type Schedule is array (Natural range 0 .. 63) of Word;

   type Context is record
      State       : State_Array;
      Buffer      : Byte_Block;
      Buf_Len     : Natural range 0 .. 63;
      Msg_Len     : Interfaces.Unsigned_64;
      Initialized : Boolean := False;
   end record;

   function Is_Initialized (Ctx : Context) return Boolean
     is (Ctx.Initialized);

   function Message_Byte_Count (Ctx : Context)
     return Interfaces.Unsigned_64
     is (Ctx.Msg_Len);

end SHA256;
