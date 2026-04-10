with Ada.Streams;

--  Generic HMAC (RFC 2104) for any hash function.
--
--  WARNING: This generic package is NOT analyzed by SPARK/gnatprove.
--  Generic formal subprograms have no contracts, so gnatprove skips
--  instantiated units. For a SPARK-proved HMAC-SHA-256, use the
--  concrete HMAC_SHA256 package instead. To get SPARK proof with
--  other hash functions, write a concrete package (like HMAC_SHA256)
--  that directly calls the hash operations with full contracts.

generic
   Block_Size  : Ada.Streams.Stream_Element_Offset;
   Digest_Size : Ada.Streams.Stream_Element_Offset;

   type Hash_Context is private;

   with procedure Hash_Init (Ctx : out Hash_Context);
   with procedure Hash_Update (Ctx  : in out Hash_Context;
                               Data : Ada.Streams.Stream_Element_Array);
   with procedure Hash_Final (Ctx    : in out Hash_Context;
                              Digest : out Ada.Streams.Stream_Element_Array);

package HMAC is

   pragma Pure;
   pragma SPARK_Mode (Off);

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;

   pragma Compile_Time_Error
     (Digest_Size > Block_Size,
      "Digest_Size must not exceed Block_Size");

   Max_Data_Length : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset'Last / 2;

   subtype HMAC_Digest is
     Ada.Streams.Stream_Element_Array (1 .. Digest_Size);

   type Context is private;

   function Is_Initialized (Ctx : Context) return Boolean;

   procedure Initialize (Ctx : out Context;
                         Key  : Ada.Streams.Stream_Element_Array)
     with Pre => Key'First >= 0
                and then Key'Last <= Max_Data_Length,
          Post => Is_Initialized (Ctx);

   procedure Update (Ctx  : in out Context;
                     Data : Ada.Streams.Stream_Element_Array)
     with Pre => Is_Initialized (Ctx)
                and then Data'First >= 0
                and then Data'Last <= Max_Data_Length;

   procedure Finalize (Ctx    : in out Context;
                       Digest : out HMAC_Digest)
     with Pre  => Is_Initialized (Ctx),
          Post => not Is_Initialized (Ctx);

   procedure Compute (Key     : Ada.Streams.Stream_Element_Array;
                      Message : Ada.Streams.Stream_Element_Array;
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
