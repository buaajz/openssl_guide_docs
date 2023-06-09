import numpy as np

arr = np.array([0x30, 0x82, 0x01, 0xe7, 0x30, 0x82, 0x01, 0x8e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x69, 0xcd, 0xf1, 0x0d, 0xe9, 0xe5,
    0x4e, 0xd1, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x3d, 0x31, 0x25, 0x30, 0x23, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x50, 0x41, 0x49, 0x20,
    0x30, 0x78, 0x46, 0x46, 0x46, 0x31, 0x20, 0x6e, 0x6f, 0x20, 0x50, 0x49, 0x44, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06,
    0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46, 0x46, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30,
    0x32, 0x30, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
    0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x53, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c, 0x4d, 0x61,
    0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x44, 0x41, 0x43, 0x20, 0x30, 0x78, 0x46, 0x46, 0x46, 0x31, 0x2f, 0x30,
    0x78, 0x38, 0x30, 0x30, 0x31, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01,
    0x0c, 0x04, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02,
    0x02, 0x0c, 0x04, 0x38, 0x30, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x46, 0x3a, 0xc6, 0x93, 0x42, 0x91, 0x0a, 0x0e,
    0x55, 0x88, 0xfc, 0x6f, 0xf5, 0x6b, 0xb6, 0x3e, 0x62, 0xec, 0xce, 0xcb, 0x14, 0x8f, 0x7d, 0x4e, 0xb0, 0x3e, 0xe5, 0x52, 0x60,
    0x14, 0x15, 0x76, 0x7d, 0x16, 0xa5, 0xc6, 0x63, 0xf7, 0x93, 0xe4, 0x91, 0x23, 0x26, 0x0b, 0x82, 0x97, 0xa7, 0xcd, 0x7e, 0x7c,
    0xfc, 0x7b, 0x31, 0x6b, 0x39, 0xd9, 0x8e, 0x90, 0xd2, 0x93, 0x77, 0x73, 0x8e, 0x82, 0xa3, 0x60, 0x30, 0x5e, 0x30, 0x0c, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
    0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x88, 0xdd, 0xe7, 0xb3,
    0x00, 0x38, 0x29, 0x32, 0xcf, 0xf7, 0x34, 0xc0, 0x46, 0x24, 0x81, 0x0f, 0x44, 0x16, 0x8a, 0x6f, 0x30, 0x1f, 0x06, 0x03, 0x55,
    0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x63, 0x54, 0x0e, 0x47, 0xf6, 0x4b, 0x1c, 0x38, 0xd1, 0x38, 0x84, 0xa4, 0x62,
    0xd1, 0x6c, 0x19, 0x5d, 0x8f, 0xfb, 0x3c, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47,
    0x00, 0x30, 0x44, 0x02, 0x20, 0x01, 0x27, 0xa2, 0x7b, 0x4b, 0x44, 0x61, 0x0e, 0xe2, 0xfc, 0xdc, 0x4d, 0x2b, 0x78, 0x85, 0x56,
    0x36, 0x60, 0xbc, 0x0f, 0x76, 0xf1, 0x72, 0x19, 0xed, 0x6a, 0x08, 0xdf, 0xb2, 0xb3, 0xc1, 0xcd, 0x02, 0x20, 0x6b, 0x59, 0xe0,
    0xaf, 0x45, 0xf3, 0xeb, 0x2a, 0x85, 0xb9, 0x19, 0xd3, 0x57, 0x31, 0x52, 0x8c, 0x60, 0x28, 0xc4, 0x15, 0x23, 0x95, 0x45, 0xe1,
    0x08, 0xe4, 0xe5, 0x4e, 0x70, 0x97, 0x13, 0x53,], dtype=np.int8)

arr.tofile("dac_mock.der")

arr1 = np.array([0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, # head
    0xaa, 0xb6, 0x00, 0xae, 0x8a, 0xe8, 0xaa, 0xb7, 0xd7, 0x36, 0x27, 0xc2, 0x17, 0xb7, 0xc2, 0x04, # pri
    0x70, 0x9c, 0xa6, 0x94, 0x6a, 0xf5, 0xfc, 0xf7, 0x53, 0x08, 0x33, 0xa5, 0x2c, 0x44, 0xfc, 0xff, # pri
    0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, # middle
    0x04, 0x46, 0x3a, 0xc6, 0x93, 0x42, 0x91, 0x0a, 0x0e, 0x55, 0x88, 0xfc, 0x6f, 0xf5, 0x6b, 0xb6, 0x3e, # pub
    0x62, 0xec, 0xce, 0xcb, 0x14, 0x8f, 0x7d, 0x4e, 0xb0, 0x3e, 0xe5, 0x52, 0x60, 0x14, 0x15, 0x76, 0x7d,
    0x16, 0xa5, 0xc6, 0x63, 0xf7, 0x93, 0xe4, 0x91, 0x23, 0x26, 0x0b, 0x82, 0x97, 0xa7, 0xcd, 0x7e, 0x7c,
    0xfc, 0x7b, 0x31, 0x6b, 0x39, 0xd9, 0x8e, 0x90, 0xd2, 0x93, 0x77, 0x73, 0x8e, 0x82, # pub
    ], dtype=np.int8)

arr1.tofile("dacpri_com_mock.der")







