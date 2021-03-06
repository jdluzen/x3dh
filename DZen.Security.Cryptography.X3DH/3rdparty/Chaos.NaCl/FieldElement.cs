﻿using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
    public struct FieldElement
    {
        public int x0;
        public int x1;
        public int x2;
        public int x3;
        public int x4;
        public int x5;
        public int x6;
        public int x7;
        public int x8;
        public int x9;

        //internal static readonly FieldElement Zero = new FieldElement();
        //internal static readonly FieldElement One = new FieldElement() { x0 = 1 };

        public FieldElement(params int[] elements)
        {
            InternalAssert.Assert(elements.Length == 10, "elements.Length != 10");
            x0 = elements[0];
            x1 = elements[1];
            x2 = elements[2];
            x3 = elements[3];
            x4 = elements[4];
            x5 = elements[5];
            x6 = elements[6];
            x7 = elements[7];
            x8 = elements[8];
            x9 = elements[9];
        }
    }
}
