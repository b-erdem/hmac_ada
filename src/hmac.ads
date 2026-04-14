with System.Storage_Elements;

--  Generic HMAC (RFC 2104) for any hash function.
--
--  WARNING: This generic package is NOT analyzed by SPARK/gnatprove.
--  Generic formal subprograms have no contracts, so gnatprove skips
--  instantiated units. For a SPARK-proved HMAC-SHA-256, use the
--  concrete HMAC_SHA256 package instead. To get SPARK proof with
--  other hash functions, write a concrete package (like HMAC_SHA256)
--  that directly calls the hash operations with full contracts.

generic
   Block_Size  : System.Storage_Elements.Storage_Offset;
   Digest_Size : System.Storage_Elements.Storage_Offset;

   type Hash_Context is private;

   with procedure Hash_Init (Ctx : out Hash_Context);
   with procedure Hash_Update (Ctx  : in out Hash_Context;
                               Data : System.Storage_Elements.Storage_Array);
   with procedure Hash_Final (Ctx    : in out Hash_Context;
                              Digest : out System.Storage_Elements.Storage_Array);

package HMAC is

   pragma Pure;
   pragma SPARK_Mode (Off);

   use type System.Storage_Elements.Storage_Element;
   use type System.Storage_Elements.Storage_Array;
   use type System.Storage_Elements.Storage_Offset;

   pragma Compile_Time_Error
     (Digest_Size > Block_Size,
      "Digest_Size must not exceed Block_Size");

   Max_Data_Length : constant System.Storage_Elements.Storage_Offset :=
     System.Storage_Elements.Storage_Offset'Last / 2;

   subtype HMAC_Digest is
     System.Storage_Elements.Storage_Array (1 .. Digest_Size);

   type Context is private;

   function Is_Initialized (Ctx : Context) return Boolean;

   procedure Initialize (Ctx : out Context;
                         Key  : System.Storage_Elements.Storage_Array)
     with Pre => Key'First >= 0
                and then Key'Last <= Max_Data_Length,
          Post => Is_Initialized (Ctx);

   procedure Update (Ctx  : in out Context;
                     Data : System.Storage_Elements.Storage_Array)
     with Pre => Is_Initialized (Ctx)
                and then Data'First >= 0
                and then Data'Last <= Max_Data_Length;

   procedure Finalize (Ctx    : in out Context;
                       Digest : out HMAC_Digest)
     with Pre  => Is_Initialized (Ctx),
          Post => not Is_Initialized (Ctx);

   procedure Compute (Key     : System.Storage_Elements.Storage_Array;
                      Message : System.Storage_Elements.Storage_Array;
                      Digest  : out HMAC_Digest)
     with Pre => Key'First >= 0
                and then Key'Last <= Max_Data_Length
                and then Message'First >= 0
                and then Message'Last <= Max_Data_Length;

   --  Constant-time digest comparison to prevent timing side-channels.
   function Equal (Left, Right : HMAC_Digest) return Boolean
     with Post => Equal'Result = (Left = Right);

private

   type Context is record
      Inner       : Hash_Context;
      Outer       : Hash_Context;
      Initialized : Boolean := False;
   end record;

   function Is_Initialized (Ctx : Context) return Boolean
     is (Ctx.Initialized);

end HMAC;
