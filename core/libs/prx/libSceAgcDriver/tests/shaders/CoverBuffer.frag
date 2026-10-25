#version 450
layout(location = 0) flat in uint word;
layout(location = 0) out vec4 color;
void main() {
    color = unpackUnorm4x8(word);
}
