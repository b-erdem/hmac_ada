package body HMAC_SHA256 is

   pragma SPARK_Mode;

   IPad_Val : constant System.Storage_Elements.Storage_Element := 16#36#;
   OPad_Val : constant System.Storage_Elements.Storage_Element := 16#5C#;

   procedure Initialize (Ctx : out Context;
                         Key  : Byte_Array) is
      K0 : Byte_Array (1 .. SHA256.Block_Length) := [others => 0];
   begin
      if Key'Length > SHA256.Block_Length then
         declare
            Key_Ctx  : SHA256.Context;
            Key_Hash : SHA256.Digest;
         begin
            SHA256.Initialize (Key_Ctx);
            SHA256.Update (Key_Ctx, Key);
            pragma Warnings (Off, "is set by ""Finalize"" but not used after the call");
            SHA256.Finalize (Key_Ctx, Key_Hash);
            pragma Warnings (On, "is set by ""Finalize"" but not used after the call");
            for I in 1 .. SHA256.Digest_Length loop
               K0 (I) := Key_Hash (I);
            end loop;
            --  Scrub intermediate key hash
            pragma Warnings (Off, "unused assignment");
            Key_Hash := [others => 0];
            pragma Inspection_Point (Key_Hash);
            pragma Warnings (On, "unused assignment");
         end;
      else
         K0 (1 .. Key'Length) := Key;
      end if;

      declare
         IPad_Key : Byte_Array (1 .. SHA256.Block_Length) := K0;
      begin
         for I in IPad_Key'Range loop
            IPad_Key (I) := IPad_Key (I) xor IPad_Val;
         end loop;
         SHA256.Initialize (Ctx.Inner);
         SHA256.Update (Ctx.Inner, IPad_Key);
         --  Scrub ipad key material
         pragma Warnings (Off, "unused assignment");
         IPad_Key := [others => 0];
         pragma Inspection_Point (IPad_Key);
         pragma Warnings (On, "unused assignment");
      end;

      declare
         OPad_Key : Byte_Array (1 .. SHA256.Block_Length) := K0;
      begin
         for I in OPad_Key'Range loop
            OPad_Key (I) := OPad_Key (I) xor OPad_Val;
         end loop;
         SHA256.Initialize (Ctx.Outer);
         SHA256.Update (Ctx.Outer, OPad_Key);
         --  Scrub opad key material
         pragma Warnings (Off, "unused assignment");
         OPad_Key := [others => 0];
         pragma Inspection_Point (OPad_Key);
         pragma Warnings (On, "unused assignment");
      end;

      --  Scrub padded key
      pragma Warnings (Off, "unused assignment");
      K0 := [others => 0];
      pragma Inspection_Point (K0);
      pragma Warnings (On, "unused assignment");
      Ctx.Initialized := True;
   end Initialize;

   procedure Update (Ctx  : in out Context;
                     Data : Byte_Array) is
   begin
      SHA256.Update (Ctx.Inner, Data);
   end Update;

   procedure Finalize (Ctx    : in out Context;
                       Digest : out HMAC_Digest) is
      Inner_Digest : SHA256.Digest;
      Outer_Digest : SHA256.Digest;
   begin
      SHA256.Finalize (Ctx.Inner, Inner_Digest);
      SHA256.Update (Ctx.Outer, Inner_Digest);
      SHA256.Finalize (Ctx.Outer, Outer_Digest);
      Digest := HMAC_Digest (Outer_Digest);
      --  Scrub intermediate digest
      pragma Warnings (Off, "unused assignment");
      Inner_Digest := [others => 0];
      pragma Inspection_Point (Inner_Digest);
      pragma Warnings (On, "unused assignment");
      Ctx.Initialized := False;
   end Finalize;

   procedure Compute (Key     : Byte_Array;
                      Message : Byte_Array;
                      Digest  : out HMAC_Digest) is
      Ctx : Context;
   begin
      Initialize (Ctx, Key);
      Update (Ctx, Message);
      pragma Warnings (Off, "is set by ""Finalize"" but not used after the call");
      Finalize (Ctx, Digest);
      pragma Warnings (On, "is set by ""Finalize"" but not used after the call");
   end Compute;

   --  Constant-time comparison — accumulates XOR differences in Diff
   --  so every byte is always visited regardless of mismatch position.
   --  No_Inline prevents interprocedural optimization from converting the
   --  accumulation into an early-exit branch. This overrides the predefined
   --  array equality, so the default `=` operator on HMAC_Digest is the
   --  constant-time one. `Equal` renames `=` (see the spec).
   function "=" (Left, Right : HMAC_Digest) return Boolean is
      Diff : System.Storage_Elements.Storage_Element := 0;
   begin
      for I in Left'Range loop
         pragma Loop_Invariant
           ((Diff = 0) =
              (for all J in Left'First .. I - 1 =>
                 Left (J) = Right (J)));
         Diff := Diff or (Left (I) xor Right (I));
      end loop;
      return Diff = 0;
   end "=";

   pragma No_Inline ("=");

end HMAC_SHA256;
