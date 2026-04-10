package body HMAC is

   pragma SPARK_Mode (Off);

   IPad_Val : constant Ada.Streams.Stream_Element := 16#36#;
   OPad_Val : constant Ada.Streams.Stream_Element := 16#5C#;

   procedure Initialize (Ctx : out Context;
                         Key  : Ada.Streams.Stream_Element_Array) is
      K0 : Ada.Streams.Stream_Element_Array (1 .. Block_Size) :=
        [others => 0];
   begin
      if Key'Length > Block_Size then
         declare
            Key_Ctx  : Hash_Context;
            Key_Hash : Ada.Streams.Stream_Element_Array (1 .. Digest_Size);
         begin
            Hash_Init (Key_Ctx);
            Hash_Update (Key_Ctx, Key);
            Hash_Final (Key_Ctx, Key_Hash);
            for I in 1 .. Digest_Size loop
               K0 (I) := Key_Hash (I);
            end loop;
            Key_Hash := [others => 0];
            pragma Inspection_Point (Key_Hash);
         end;
      else
         K0 (1 .. Key'Length) := Key;
      end if;

      declare
         IPad_Key : Ada.Streams.Stream_Element_Array (1 .. Block_Size) := K0;
      begin
         for I in IPad_Key'Range loop
            IPad_Key (I) := IPad_Key (I) xor IPad_Val;
         end loop;
         Hash_Init (Ctx.Inner);
         Hash_Update (Ctx.Inner, IPad_Key);
         IPad_Key := [others => 0];
         pragma Inspection_Point (IPad_Key);
      end;

      declare
         OPad_Key : Ada.Streams.Stream_Element_Array (1 .. Block_Size) := K0;
      begin
         for I in OPad_Key'Range loop
            OPad_Key (I) := OPad_Key (I) xor OPad_Val;
         end loop;
         Hash_Init (Ctx.Outer);
         Hash_Update (Ctx.Outer, OPad_Key);
         OPad_Key := [others => 0];
         pragma Inspection_Point (OPad_Key);
      end;

      K0 := [others => 0];
      pragma Inspection_Point (K0);
      Ctx.Initialized := True;
   end Initialize;

   procedure Update (Ctx  : in out Context;
                     Data : Ada.Streams.Stream_Element_Array) is
   begin
      Hash_Update (Ctx.Inner, Data);
   end Update;

   procedure Finalize (Ctx    : in out Context;
                       Digest : out HMAC_Digest) is
      Inner_Digest : Ada.Streams.Stream_Element_Array (1 .. Digest_Size);
   begin
      Hash_Final (Ctx.Inner, Inner_Digest);
      Hash_Update (Ctx.Outer, Inner_Digest);
      Hash_Final (Ctx.Outer, Digest);
      Inner_Digest := [others => 0];
      pragma Inspection_Point (Inner_Digest);
      Ctx.Initialized := False;
   end Finalize;

   procedure Compute (Key     : Ada.Streams.Stream_Element_Array;
                      Message : Ada.Streams.Stream_Element_Array;
                      Digest  : out HMAC_Digest) is
      Ctx : Context;
   begin
      Initialize (Ctx, Key);
      Update (Ctx, Message);
      Finalize (Ctx, Digest);
   end Compute;

   --  Constant-time comparison — accumulates XOR differences so
   --  every byte is always visited regardless of mismatch position.
   --  No_Inline prevents interprocedural optimization from converting the
   --  accumulation into an early-exit branch.
   function Equal (Left, Right : HMAC_Digest) return Boolean is
      Diff : Ada.Streams.Stream_Element := 0;
   begin
      for I in Left'Range loop
         Diff := Diff or (Left (I) xor Right (I));
      end loop;
      return Diff = 0;
   end Equal;

   pragma No_Inline (Equal);

end HMAC;
