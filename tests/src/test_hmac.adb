with System.Storage_Elements;
with Ada.Text_IO;
with Ada.Command_Line;
with SHA256;
with HMAC_SHA256;

procedure Test_HMAC is

   use type System.Storage_Elements.Storage_Element;
   use type System.Storage_Elements.Storage_Offset;
   use type System.Storage_Elements.Storage_Array;

   package SE renames System.Storage_Elements;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   function Hex_Val (C : Character) return SE.Storage_Element is
     (case C is
         when '0' .. '9' => SE.Storage_Element
           (Character'Pos (C) - Character'Pos ('0')),
         when 'a' .. 'f' => SE.Storage_Element
           (Character'Pos (C) - Character'Pos ('a') + 10),
         when 'A' .. 'F' => SE.Storage_Element
           (Character'Pos (C) - Character'Pos ('A') + 10),
         when others => 0);

   function H (Hex : String) return SE.Storage_Array is
      Len    : constant SE.Storage_Offset := Hex'Length / 2;
      Result : SE.Storage_Array (1 .. Len);
   begin
      for I in 1 .. Len loop
         declare
            II : constant Integer := Integer (I - 1);
         begin
            Result (I) :=
              Hex_Val (Hex (Hex'First + II * 2)) * 16 +
              Hex_Val (Hex (Hex'First + II * 2 + 1));
         end;
      end loop;
      return Result;
   end H;

   Hex_Chars : constant String := "0123456789abcdef";

   function To_Hex (Data : SE.Storage_Array) return String is
      Result : String (1 .. Integer (Data'Length) * 2);
   begin
      for I in Data'Range loop
         declare
            V   : constant SE.Storage_Element := Data (I);
            Pos : constant Integer :=
              Integer (I - Data'First) * 2 + 1;
         begin
            Result (Pos)     := Hex_Chars (Natural (V / 16) + 1);
            Result (Pos + 1) := Hex_Chars (Natural (V mod 16) + 1);
         end;
      end loop;
      return Result;
   end To_Hex;

   procedure Check (Name     : String;
                    Got      : SE.Storage_Array;
                    Expected : SE.Storage_Array) is
   begin
      if Got'Length = Expected'Length and then Got = Expected then
         Ada.Text_IO.Put_Line ("PASS: " & Name);
         Pass_Count := Pass_Count + 1;
      else
         Ada.Text_IO.Put_Line ("FAIL: " & Name);
         Ada.Text_IO.Put_Line ("  Expected: " & To_Hex (Expected));
         Ada.Text_IO.Put_Line ("  Got:      " & To_Hex (Got));
         Fail_Count := Fail_Count + 1;
      end if;
   end Check;

   procedure Check_Bool (Name     : String;
                         Got      : Boolean;
                         Expected : Boolean) is
   begin
      if Got = Expected then
         Ada.Text_IO.Put_Line ("PASS: " & Name);
         Pass_Count := Pass_Count + 1;
      else
         Ada.Text_IO.Put_Line ("FAIL: " & Name);
         Ada.Text_IO.Put_Line ("  Expected: " & Boolean'Image (Expected));
         Ada.Text_IO.Put_Line ("  Got:      " & Boolean'Image (Got));
         Fail_Count := Fail_Count + 1;
      end if;
   end Check_Bool;

   procedure Test_SHA256 (Name     : String;
                          Message  : SE.Storage_Array;
                          Expected : String) is
      Ctx    : SHA256.Context;
      Digest : SHA256.Digest;
   begin
      SHA256.Initialize (Ctx);
      SHA256.Update (Ctx, Message);
      SHA256.Finalize (Ctx, Digest);
      Check (Name, Digest, H (Expected));
   end Test_SHA256;

   procedure Test_HMAC (Name     : String;
                         Key      : SE.Storage_Array;
                         Message  : SE.Storage_Array;
                         Expected : String) is
      Digest : HMAC_SHA256.HMAC_Digest;
   begin
      HMAC_SHA256.Compute (Key, Message, Digest);
      Check (Name, SE.Storage_Array (Digest), H (Expected));
   end Test_HMAC;

   procedure Test_HMAC_Stream
     (Name     : String;
      Key      : SE.Storage_Array;
      Chunks   : SE.Storage_Array;
      Expected : String) is
      Ctx    : HMAC_SHA256.Context;
      Digest : HMAC_SHA256.HMAC_Digest;
      Mid    : constant SE.Storage_Offset :=
        Chunks'First + Chunks'Length / 2;
   begin
      HMAC_SHA256.Initialize (Ctx, Key);
      if Mid > Chunks'First then
         HMAC_SHA256.Update (Ctx, Chunks (Chunks'First .. Mid - 1));
      end if;
      if Mid <= Chunks'Last then
         HMAC_SHA256.Update (Ctx, Chunks (Mid .. Chunks'Last));
      end if;
      HMAC_SHA256.Finalize (Ctx, Digest);
      Check (Name, SE.Storage_Array (Digest), H (Expected));
   end Test_HMAC_Stream;

begin
   Ada.Text_IO.Put_Line ("=== SHA-256 Tests ===");

   Test_SHA256 ("SHA-256 empty",
     H (""),
     "e3b0c44298fc1c149afbf4c8996fb924"
     & "27ae41e4649b934ca495991b7852b855");

   Test_SHA256 ("SHA-256 'abc'",
     H ("616263"),
     "ba7816bf8f01cfea414140de5dae2223"
     & "b00361a396177a9cb410ff61f20015ad");

   Test_SHA256 ("SHA-256 two-block (56 bytes)",
     H ("61626364626364656364656664656667"
       & "65666768666768696768696a68696a6b"
       & "696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f"
       & "6d6e6f706e6f7071"),
     "248d6a61d20638b8e5c026930c3e6039"
     & "a33ce45964ff2167f6ecedd419db06c1");

   Test_SHA256 ("SHA-256 64 bytes (exact block)",
     H ("00000000000000000000000000000000"
       & "00000000000000000000000000000000"
       & "00000000000000000000000000000000"
       & "00000000000000000000000000000000"),
     "f5a5fd42d16a20302798ef6ed309979b"
     & "43003d2320d9f0e8ea9831a92759fb4b");

   Test_SHA256 ("SHA-256 65 bytes (2 blocks)",
     H ("000102030405060708090a0b0c0d0e0f"
       & "101112131415161718191a1b1c1d1e1f"
       & "202122232425262728292a2b2c2d2e2f"
       & "303132333435363738393a3b3c3d3e3f"
       & "40"),
     "4bfd2c8b6f1eec7a2afeb48b934ee4b2"
     & "694182027e6d0fc075074f2fabb31781");

   --  SHA-256 multi-update — verifies buffer accumulation across calls
   declare
      Ctx    : SHA256.Context;
      Digest : SHA256.Digest;
   begin
      SHA256.Initialize (Ctx);
      SHA256.Update (Ctx, H ("6162"));
      SHA256.Update (Ctx, H ("63"));
      SHA256.Finalize (Ctx, Digest);
      Check ("SHA-256 multi-update 'abc'",
        Digest,
        H ("ba7816bf8f01cfea414140de5dae2223"
         & "b00361a396177a9cb410ff61f20015ad"));
   end;

   Ada.Text_IO.New_Line;
   Ada.Text_IO.Put_Line ("=== HMAC-SHA-256 RFC 4231 ===");

   declare
      Key : constant SE.Storage_Array := [1 .. 20 => 16#0b#];
   begin
      Test_HMAC ("TC1: key=0b*20, 'Hi There'",
        Key, H ("4869205468657265"),
        "b0344c61d8db38535ca8afceaf0bf12b"
        & "881dc200c9833da726e9376c2e32cff7");
   end;

   declare
      Key : constant SE.Storage_Array := H ("4a656665");
   begin
      Test_HMAC ("TC2: key='Jefe'",
        Key, H ("7768617420646f2079612077616e7420"
                & "666f72206e6f7468696e673f"),
        "5bdcc146bf60754e6a042426089575c7"
        & "5a003f089d2739839dec58b964ec3843");
   end;

   declare
       Key : constant SE.Storage_Array := [1 .. 20 => 16#aa#];
   begin
      Test_HMAC ("TC3: key=aa*20, data=dd*50",
        Key,
        H ("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
         & "dddddddddddddddddddddddddddddddddddd"),
        "773ea91e36800e46854db8ebd09181a7"
        & "2959098b3ef8c122d9635514ced565fe");
   end;

   declare
      Key : constant SE.Storage_Array :=
        H ("0102030405060708090a0b0c0d0e0f10"
           & "111213141516171819");
   begin
      Test_HMAC ("TC4: key=01..19, data=cd*50",
        Key,
        H ("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
         & "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
        "82558a389a443c0ea4cc819899f2083a"
        & "85f0faa3e578f8077a2e3ff46729665b");
   end;

   declare
      Key : constant SE.Storage_Array := [1 .. 20 => 16#0c#];
   begin
      Test_HMAC ("TC5: key=0c*20, 'Test With Truncation'",
        Key, H ("546573742057697468205472756e6361"
                & "74696f6e"),
        "a3b6167473100ee06e0c796c2955552b"
        & "fa6f7c0a6a8aef8b93f860aab0cd20c5");
   end;

   declare
      Key : constant SE.Storage_Array := [1 .. 131 => 16#aa#];
   begin
      Test_HMAC ("TC6: key=aa*131 (key>block)",
        Key, H ("54657374205573696e67204c61726765"
                & "72205468616e20426c6f636b2d53697a"
                & "65204b6579202d2048617368204b6579"
                & "204669727374"),
        "60e431591ee0b67f0d8a26aacbf5b77f"
        & "8e0bc6213728c5140546040f0ee37f54");
   end;

   declare
      Key : constant SE.Storage_Array := [1 .. 131 => 16#aa#];
   begin
      Test_HMAC ("TC7: key=aa*131, long data",
        Key, H ("54686973206973206120746573742075"
                & "73696e672061206c6172676572207468"
                & "616e20626c6f636b2d73697a65206b65"
                & "7920616e642061206c61726765722074"
                & "68616e20626c6f636b2d73697a652064"
                & "6174612e20546865206b6579206e6565"
                & "647320746f2062652068617368656420"
                & "6265666f7265206265696e6720757365"
                & "642062792074686520484d414320616c"
                & "676f726974686d2e"),
        "9b09ffa71b942fcb27635fbcd5b0e944"
        & "bfdc63644f0713938a7f51535c3a35e2");
   end;

   Ada.Text_IO.New_Line;
   Ada.Text_IO.Put_Line ("=== Streaming HMAC Tests ===");

   declare
      Key : constant SE.Storage_Array := [1 .. 20 => 16#0b#];
   begin
      Test_HMAC_Stream ("Stream TC1: 2-chunk",
        Key, H ("4869205468657265"),
        "b0344c61d8db38535ca8afceaf0bf12b"
        & "881dc200c9833da726e9376c2e32cff7");
   end;

   declare
      Key : constant SE.Storage_Array := H ("4a656665");
   begin
      Test_HMAC_Stream ("Stream TC2: 2-chunk",
        Key, H ("7768617420646f2079612077616e7420666f"
                & "72206e6f7468696e673f"),
        "5bdcc146bf60754e6a042426089575c7"
        & "5a003f089d2739839dec58b964ec3843");
   end;

   declare
      Key  : constant SE.Storage_Array := [1 .. 20 => 16#aa#];
      Data : constant SE.Storage_Array := [1 .. 50 => 16#dd#];
   begin
      Test_HMAC_Stream ("Stream TC3: 2-chunk 50-byte",
        Key, Data,
        "773ea91e36800e46854db8ebd09181a7"
        & "2959098b3ef8c122d9635514ced565fe");
   end;

   declare
      Key : constant SE.Storage_Array := [1 .. 131 => 16#aa#];
   begin
      Test_HMAC_Stream ("Stream TC6: key>block",
        Key, H ("54657374205573696e67204c61726765"
                & "72205468616e20426c6f636b2d53697a"
                & "65204b6579202d2048617368204b6579"
                & "204669727374"),
        "60e431591ee0b67f0d8a26aacbf5b77f"
        & "8e0bc6213728c5140546040f0ee37f54");
   end;


   Ada.Text_IO.New_Line;
   Ada.Text_IO.Put_Line ("=== Edge Case Tests ===");

   --  Empty message
   declare
      Key : constant SE.Storage_Array := [1 .. 20 => 16#0b#];
   begin
      Test_HMAC ("Edge: empty message",
        Key, H (""),
        "999a901219f032cd497cadb5e6051e97"
        & "b6a29ab297bd6ae722bd6062a2f59542");
   end;

   --  Empty key
   declare
      Key : constant SE.Storage_Array (1 .. 0) :=
        [others => 0];
   begin
      Test_HMAC ("Edge: empty key",
        Key, H ("4869205468657265"),
        "e48411262715c8370cd5e7bf8e82bef5"
        & "3bd53712d007f3429351843b77c7bb9b");
   end;

   --  64-byte key (exactly block size)
   declare
      Key : SE.Storage_Array (1 .. 64);
   begin
      for I in Key'Range loop
         Key (I) := SE.Storage_Element ((I - 1) mod 256);
      end loop;
      Test_HMAC ("Edge: 64-byte key (exact block)",
        Key, H ("53616d706c65206d657373616765"),
        "cb0937119a6ca4137952ad98fc798c78"
        & "3c70eed4a03320760f400bdd2a957c04");
   end;

   --  65-byte key (just over block size, triggers key hashing)
   declare
      Key : SE.Storage_Array (1 .. 65);
   begin
      for I in Key'Range loop
         Key (I) := SE.Storage_Element ((I - 1) mod 256);
      end loop;
      Test_HMAC ("Edge: 65-byte key (over block, hashed)",
        Key, H ("53616d706c65206d657373616765"),
        "ff13f0ee75fce95ef5c21df53398d2aa"
        & "324d7e2657de1b84f3c0c05cdde9c5ef");
   end;


   Ada.Text_IO.New_Line;
   Ada.Text_IO.Put_Line ("=== Constant-Time Equal Tests ===");

   declare
      D1 : HMAC_SHA256.HMAC_Digest;
      D2 : HMAC_SHA256.HMAC_Digest;
      Key : constant SE.Storage_Array := [1 .. 20 => 16#0b#];
      Msg : constant SE.Storage_Array := H ("4869205468657265");
   begin
      HMAC_SHA256.Compute (Key, Msg, D1);
      HMAC_SHA256.Compute (Key, Msg, D2);
      Check_Bool ("Equal: identical digests", HMAC_SHA256.Equal (D1, D2), True);

      --  Flip one bit
      D2 (1) := D2 (1) xor 1;
      Check_Bool ("Equal: single-bit diff", HMAC_SHA256.Equal (D1, D2), False);

      --  Flip last byte
      D2 := D1;
      D2 (32) := D2 (32) xor 16#FF#;
      Check_Bool ("Equal: last-byte diff", HMAC_SHA256.Equal (D1, D2), False);

      --  All zeros vs all ones
      D1 := [others => 0];
      D2 := [others => 16#FF#];
      Check_Bool ("Equal: all-zero vs all-FF", HMAC_SHA256.Equal (D1, D2), False);

      --  Both zero
      D2 := [others => 0];
      Check_Bool ("Equal: both all-zero", HMAC_SHA256.Equal (D1, D2), True);
   end;

   Ada.Text_IO.New_Line;
   Ada.Text_IO.Put_Line
     ("Total:" & Natural'Image (Pass_Count) & " passed,"
      & Natural'Image (Fail_Count) & " failed");

   if Fail_Count > 0 then
      Ada.Text_IO.Put_Line ("SOME TESTS FAILED");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Ada.Text_IO.Put_Line ("ALL TESTS PASSED");
   end if;

end Test_HMAC;
