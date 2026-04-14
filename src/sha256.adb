package body SHA256 is

   pragma SPARK_Mode;

   use type Interfaces.Unsigned_32;

   Initial_State : constant State_Array :=
     [16#6a09_e667#, 16#bb67_ae85#, 16#3c6e_f372#, 16#a54f_f53a#,
      16#510e_527f#, 16#9b05_688c#, 16#1f83_d9ab#, 16#5be0_cd19#];

   K : constant Schedule :=
     [16#428a_2f98#, 16#7137_4491#, 16#b5c0_fbcf#, 16#e9b5_dba5#,
      16#3956_c25b#, 16#59f1_11f1#, 16#923f_82a4#, 16#ab1c_5ed5#,
      16#d807_aa98#, 16#1283_5b01#, 16#2431_85be#, 16#550c_7dc3#,
      16#72be_5d74#, 16#80de_b1fe#, 16#9bdc_06a7#, 16#c19b_f174#,
      16#e49b_69c1#, 16#efbe_4786#, 16#0fc1_9dc6#, 16#240c_a1cc#,
      16#2de9_2c6f#, 16#4a74_84aa#, 16#5cb0_a9dc#, 16#76f9_88da#,
      16#983e_5152#, 16#a831_c66d#, 16#b003_27c8#, 16#bf59_7fc7#,
      16#c6e0_0bf3#, 16#d5a7_9147#, 16#06ca_6351#, 16#1429_2967#,
      16#27b7_0a85#, 16#2e1b_2138#, 16#4d2c_6dfc#, 16#5338_0d13#,
      16#650a_7354#, 16#766a_0abb#, 16#81c2_c92e#, 16#9272_2c85#,
      16#a2bf_e8a1#, 16#a81a_664b#, 16#c24b_8b70#, 16#c76c_51a3#,
      16#d192_e819#, 16#d699_0624#, 16#f40e_3585#, 16#106a_a070#,
      16#19a4_c116#, 16#1e37_6c08#, 16#2748_774c#, 16#34b0_bcb5#,
      16#391c_0cb3#, 16#4ed8_aa4a#, 16#5b9c_ca4f#, 16#682e_6ff3#,
      16#748f_82ee#, 16#78a5_636f#, 16#84c8_7814#, 16#8cc7_0208#,
      16#90be_fffa#, 16#a450_6ceb#, 16#bef9_a3f7#, 16#c671_78f2#];

   function SHR (X : Word; N : Natural) return Word is
     (Interfaces.Shift_Right (X, N));

   function ROTR (X : Word; N : Natural) return Word is
     (Interfaces.Rotate_Right (X, N));

   function Ch (X, Y, Z : Word) return Word is
     ((X and Y) xor ((not X) and Z));

   function Maj (X, Y, Z : Word) return Word is
     ((X and Y) xor (X and Z) xor (Y and Z));

   function Upper_Sigma0 (X : Word) return Word is
     (ROTR (X, 2) xor ROTR (X, 13) xor ROTR (X, 22));

   function Upper_Sigma1 (X : Word) return Word is
     (ROTR (X, 6) xor ROTR (X, 11) xor ROTR (X, 25));

   function Lower_Sigma0 (X : Word) return Word is
     (ROTR (X, 7) xor ROTR (X, 18) xor SHR (X, 3));

   function Lower_Sigma1 (X : Word) return Word is
     (ROTR (X, 17) xor ROTR (X, 19) xor SHR (X, 10));

   function To_U8 (B : System.Storage_Elements.Storage_Element)
     return Interfaces.Unsigned_8 is
     (Interfaces.Unsigned_8 (B));

   function To_SE (B : Interfaces.Unsigned_8)
     return System.Storage_Elements.Storage_Element is
     (System.Storage_Elements.Storage_Element (B));

   function Get_Word (B : Byte_Block; I : Natural) return Word is
     (Word (B (I * 4)) * 16#0100_0000# +
      Word (B (I * 4 + 1)) * 16#0001_0000# +
      Word (B (I * 4 + 2)) * 16#0000_0100# +
      Word (B (I * 4 + 3)))
     with Pre => I < 16;

   procedure Transform (Ctx : in out Context) is
      W : Schedule := [others => 0];
      A, B, C, D, E, F, G, H : Word;
      T1, T2 : Word;
   begin
      for I in 0 .. 15 loop
         W (I) := Get_Word (Ctx.Buffer, I);
      end loop;

      for I in 16 .. 63 loop
         W (I) := Lower_Sigma1 (W (I - 2)) + W (I - 7) +
                  Lower_Sigma0 (W (I - 15)) + W (I - 16);
      end loop;

      A := Ctx.State (0);
      B := Ctx.State (1);
      C := Ctx.State (2);
      D := Ctx.State (3);
      E := Ctx.State (4);
      F := Ctx.State (5);
      G := Ctx.State (6);
      H := Ctx.State (7);

      for I in 0 .. 63 loop
         T1 := H + Upper_Sigma1 (E) + Ch (E, F, G) + K (I) + W (I);
         T2 := Upper_Sigma0 (A) + Maj (A, B, C);
         H := G;
         G := F;
         F := E;
         E := D + T1;
         D := C;
         C := B;
         B := A;
         A := T1 + T2;
      end loop;

      Ctx.State (0) := Ctx.State (0) + A;
      Ctx.State (1) := Ctx.State (1) + B;
      Ctx.State (2) := Ctx.State (2) + C;
      Ctx.State (3) := Ctx.State (3) + D;
      Ctx.State (4) := Ctx.State (4) + E;
      Ctx.State (5) := Ctx.State (5) + F;
      Ctx.State (6) := Ctx.State (6) + G;
      Ctx.State (7) := Ctx.State (7) + H;

      --  Scrub working variables — W contains key-derived material
      --  during HMAC key-processing blocks; A..H/T1/T2 hold intermediate
      --  hash state.  Defense-in-depth consistent with wipe policy elsewhere.
      pragma Warnings (Off, "unused assignment");
      W  := [others => 0];
      A  := 0;  B := 0;  C := 0;  D := 0;
      E  := 0;  F := 0;  G := 0;  H := 0;
      T1 := 0;  T2 := 0;
      pragma Warnings (On, "unused assignment");
      pragma Inspection_Point (W);
      pragma Inspection_Point (A);
      pragma Inspection_Point (B);
      pragma Inspection_Point (C);
      pragma Inspection_Point (D);
      pragma Inspection_Point (E);
      pragma Inspection_Point (F);
      pragma Inspection_Point (G);
      pragma Inspection_Point (H);
      pragma Inspection_Point (T1);
      pragma Inspection_Point (T2);
   end Transform;

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx.State := Initial_State;
      Ctx.Buffer := [others => 0];
      Ctx.Buf_Len := 0;
      Ctx.Msg_Len := 0;
      Ctx.Initialized := True;
   end Initialize;

   procedure Update (Ctx  : in out Context;
                     Data : System.Storage_Elements.Storage_Array) is
      BL : Natural;
   begin
      BL := Ctx.Buf_Len;
      for I in Data'Range loop
         pragma Loop_Invariant (BL in 0 .. 63);
         Ctx.Buffer (BL) := To_U8 (Data (I));
         if BL = 63 then
            pragma Warnings (Off, "unused assignment");
            Transform (Ctx);
            pragma Warnings (On, "unused assignment");
            BL := 0;
         else
            BL := BL + 1;
         end if;
      end loop;
      Ctx.Buf_Len := BL;
      Ctx.Msg_Len := Ctx.Msg_Len +
        Interfaces.Unsigned_64 (Data'Length);
   end Update;

   procedure Set_BE64 (B : in out Byte_Block;
                       Offset : Natural;
                       Val    : Interfaces.Unsigned_64) is
   begin
      B (Offset)     := Interfaces.Unsigned_8
        (Interfaces.Shift_Right (Val, 56) and 16#FF#);
      B (Offset + 1) := Interfaces.Unsigned_8
        (Interfaces.Shift_Right (Val, 48) and 16#FF#);
      B (Offset + 2) := Interfaces.Unsigned_8
        (Interfaces.Shift_Right (Val, 40) and 16#FF#);
      B (Offset + 3) := Interfaces.Unsigned_8
        (Interfaces.Shift_Right (Val, 32) and 16#FF#);
      B (Offset + 4) := Interfaces.Unsigned_8
        (Interfaces.Shift_Right (Val, 24) and 16#FF#);
      B (Offset + 5) := Interfaces.Unsigned_8
        (Interfaces.Shift_Right (Val, 16) and 16#FF#);
      B (Offset + 6) := Interfaces.Unsigned_8
        (Interfaces.Shift_Right (Val, 8) and 16#FF#);
      B (Offset + 7) := Interfaces.Unsigned_8
        (Val and 16#FF#);
   end Set_BE64;

   procedure Finalize (Ctx : in out Context;
                       Output : out Digest) is
      Bit_Len : constant Interfaces.Unsigned_64 := Ctx.Msg_Len * 8;
      BL : Natural;
   begin
      BL := Ctx.Buf_Len;
      Ctx.Buffer (BL) := 16#80#;
      BL := BL + 1;

      if BL <= 56 then
         for I in BL .. 55 loop
            Ctx.Buffer (I) := 0;
         end loop;
         Set_BE64 (Ctx.Buffer, 56, Bit_Len);
         pragma Warnings (Off, "unused assignment");
         Transform (Ctx);
         pragma Warnings (On, "unused assignment");
      else
         for I in BL .. 63 loop
            Ctx.Buffer (I) := 0;
         end loop;
         pragma Warnings (Off, "unused assignment");
         Transform (Ctx);
         pragma Warnings (On, "unused assignment");
         Ctx.Buffer := [others => 0];
         Set_BE64 (Ctx.Buffer, 56, Bit_Len);
         pragma Warnings (Off, "unused assignment");
         Transform (Ctx);
         pragma Warnings (On, "unused assignment");
      end if;

      Output := [others => 0];
      for I in 0 .. 7 loop
         Output (System.Storage_Elements.Storage_Offset (4 * I + 1)) :=
           To_SE (Interfaces.Unsigned_8
             (Interfaces.Shift_Right (Ctx.State (I), 24)
              and 16#FF#));
         Output (System.Storage_Elements.Storage_Offset (4 * I + 2)) :=
           To_SE (Interfaces.Unsigned_8
             (Interfaces.Shift_Right (Ctx.State (I), 16)
              and 16#FF#));
         Output (System.Storage_Elements.Storage_Offset (4 * I + 3)) :=
           To_SE (Interfaces.Unsigned_8
             (Interfaces.Shift_Right (Ctx.State (I), 8)
              and 16#FF#));
         Output (System.Storage_Elements.Storage_Offset (4 * I + 4)) :=
           To_SE (Interfaces.Unsigned_8
             (Ctx.State (I) and 16#FF#));
      end loop;

      --  Scrub sensitive internal state (defense-in-depth).
      --  Inspection_Point prevents dead-store elimination (RM H.3.2)
      --  and counts as a "use" for SPARK flow analysis (SPARK RM 7.1.3).
      Ctx.State   := [others => 0];
      Ctx.Buffer  := [others => 0];
      Ctx.Buf_Len := 0;
      Ctx.Msg_Len := 0;
      Ctx.Initialized := False;
      pragma Inspection_Point (Ctx);
   end Finalize;

end SHA256;
