with System.Storage_Elements;
with Interfaces;
with SHA256;

package HMAC_SHA256 is

   pragma Pure;
   pragma SPARK_Mode;
   pragma Unevaluated_Use_Of_Old (Allow);

   use type System.Storage_Elements.Storage_Element;
   use type System.Storage_Elements.Storage_Array;
   use type System.Storage_Elements.Storage_Offset;
   use type Interfaces.Unsigned_64;

   Max_Data_Length : constant System.Storage_Elements.Storage_Offset :=
     SHA256.Max_Data_Length;

   subtype HMAC_Digest is SHA256.Digest;

   type Context is private;

   function Is_Initialized (Ctx : Context) return Boolean
     with Ghost;

   function Inner_Is_Initialized (Ctx : Context) return Boolean
     with Ghost;

   function Outer_Is_Initialized (Ctx : Context) return Boolean
     with Ghost;

   function Inner_Byte_Count (Ctx : Context) return Interfaces.Unsigned_64
     with Ghost;

   function Outer_Byte_Count (Ctx : Context) return Interfaces.Unsigned_64
     with Ghost;

   procedure Initialize (Ctx : out Context;
                         Key  : System.Storage_Elements.Storage_Array)
     with Pre  => Key'First >= 0
                 and then Key'Last <= Max_Data_Length
                 and then Interfaces.Unsigned_64 (Key'Length) <=
                   SHA256.Max_Message_Bytes,
          Post => Is_Initialized (Ctx)
                 and then Inner_Is_Initialized (Ctx)
                 and then Outer_Is_Initialized (Ctx)
                 and then Inner_Byte_Count (Ctx) =
                   Interfaces.Unsigned_64 (SHA256.Block_Length)
                 and then Outer_Byte_Count (Ctx) =
                   Interfaces.Unsigned_64 (SHA256.Block_Length);

   procedure Update (Ctx  : in out Context;
                     Data : System.Storage_Elements.Storage_Array)
     with Pre  => Is_Initialized (Ctx)
                 and then Inner_Is_Initialized (Ctx)
                 and then Outer_Is_Initialized (Ctx)
                 and then Data'First >= 0
                 and then Data'Last <= Max_Data_Length
                 and then Interfaces.Unsigned_64 (Data'Length) <=
                   SHA256.Max_Message_Bytes
                 and then Inner_Byte_Count (Ctx) <=
                   SHA256.Max_Message_Bytes
                     - Interfaces.Unsigned_64 (Data'Length),
          Post => Is_Initialized (Ctx)
                 and then Inner_Is_Initialized (Ctx)
                 and then Outer_Is_Initialized (Ctx)
                 and then Inner_Byte_Count (Ctx) <=
                   SHA256.Max_Message_Bytes
                 and then Inner_Byte_Count (Ctx) =
                   Inner_Byte_Count (Ctx)'Old
                     + Interfaces.Unsigned_64 (Data'Length)
                 and then Outer_Byte_Count (Ctx) =
                   Outer_Byte_Count (Ctx)'Old,
          Depends => (Ctx =>+ Data);

   procedure Finalize (Ctx    : in out Context;
                       Digest : out HMAC_Digest)
     with Pre  => Is_Initialized (Ctx)
                 and then Inner_Is_Initialized (Ctx)
                 and then Outer_Is_Initialized (Ctx)
                 and then Outer_Byte_Count (Ctx) <=
                   SHA256.Max_Message_Bytes
                     - Interfaces.Unsigned_64 (SHA256.Digest_Length),
          Post => not Is_Initialized (Ctx),
          Depends => (Digest => Ctx, Ctx => Ctx);

   procedure Compute (Key     : System.Storage_Elements.Storage_Array;
                      Message : System.Storage_Elements.Storage_Array;
                      Digest  : out HMAC_Digest)
     with Pre => Key'First >= 0
                and then Key'Last <= Max_Data_Length
                and then Interfaces.Unsigned_64 (Key'Length) <=
                  SHA256.Max_Message_Bytes
                and then Message'First >= 0
                and then Message'Last <= Max_Data_Length
                and then Interfaces.Unsigned_64 (Message'Length) <=
                  SHA256.Max_Message_Bytes
                    - Interfaces.Unsigned_64 (SHA256.Block_Length);

   --  Constant-time digest comparison to prevent timing side-channels.
   --  Use this instead of "=" when comparing an expected HMAC against a
   --  computed one.
   function Equal (Left, Right : HMAC_Digest) return Boolean
     with Post => Equal'Result = (Left = Right);

private

   pragma SPARK_Mode;

   type Context is record
      Inner       : SHA256.Context;
      Outer       : SHA256.Context;
      Initialized : Boolean := False;
   end record;

   function Is_Initialized (Ctx : Context) return Boolean
     is (Ctx.Initialized);

   function Inner_Is_Initialized (Ctx : Context) return Boolean
     is (SHA256.Is_Initialized (Ctx.Inner));

   function Outer_Is_Initialized (Ctx : Context) return Boolean
     is (SHA256.Is_Initialized (Ctx.Outer));

   function Inner_Byte_Count (Ctx : Context) return Interfaces.Unsigned_64
     is (SHA256.Message_Byte_Count (Ctx.Inner));

   function Outer_Byte_Count (Ctx : Context) return Interfaces.Unsigned_64
     is (SHA256.Message_Byte_Count (Ctx.Outer));

end HMAC_SHA256;
