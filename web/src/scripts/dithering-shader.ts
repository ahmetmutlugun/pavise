// Vanilla-TS port of the 21st.dev DitheringShader (WebGL2). One canvas, one RAF loop.

const DitheringShapes = {
    simplex: 1, warp: 2, dots: 3, wave: 4, ripple: 5, swirl: 6, sphere: 7,
} as const;
const DitheringTypes = {
    random: 1, '2x2': 2, '4x4': 3, '8x8': 4,
} as const;

export type DitheringShape = keyof typeof DitheringShapes;
export type DitheringType = keyof typeof DitheringTypes;

export interface DitheringParams {
    speed: number;
    pxSize: number;
    waveAmp: number;
    bandWidth: number;
}

export interface DitheringHandle {
    params: DitheringParams;
    destroy: () => void;
}

export interface DitheringOptions {
    canvas: HTMLCanvasElement;
    colorBack: string;
    colorFront: string;
    shape?: DitheringShape;
    type?: DitheringType;
    params?: Partial<DitheringParams>;
}

const vertexShaderSource = `#version 300 es
precision mediump float;
layout(location = 0) in vec4 a_position;
void main() { gl_Position = a_position; }
`;

const fragmentShaderSource = `#version 300 es
precision mediump float;

uniform float u_time;
uniform vec2  u_resolution;
uniform vec4  u_colorBack;
uniform vec4  u_colorFront;
uniform float u_shape;
uniform float u_type;
uniform float u_pxSize;
uniform float u_waveAmp;
uniform float u_bandWidth;

out vec4 fragColor;

#define TWO_PI 6.28318530718
#define PI 3.14159265358979323846

vec3 permute(vec3 x) { return mod(((x * 34.0) + 1.0) * x, 289.0); }
float snoise(vec2 v) {
    const vec4 C = vec4(0.211324865405187, 0.366025403784439,
        -0.577350269189626, 0.024390243902439);
    vec2 i = floor(v + dot(v, C.yy));
    vec2 x0 = v - i + dot(i, C.xx);
    vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
    vec4 x12 = x0.xyxy + C.xxzz;
    x12.xy -= i1;
    i = mod(i, 289.0);
    vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0)) + i.x + vec3(0.0, i1.x, 1.0));
    vec3 m = max(0.5 - vec3(dot(x0, x0), dot(x12.xy, x12.xy), dot(x12.zw, x12.zw)), 0.0);
    m = m * m; m = m * m;
    vec3 x = 2.0 * fract(p * C.www) - 1.0;
    vec3 h = abs(x) - 0.5;
    vec3 ox = floor(x + 0.5);
    vec3 a0 = x - ox;
    m *= 1.79284291400159 - 0.85373472095314 * (a0 * a0 + h * h);
    vec3 g;
    g.x = a0.x * x0.x + h.x * x0.y;
    g.yz = a0.yz * x12.xz + h.yz * x12.yw;
    return 130.0 * dot(m, g);
}

float hash11(float p) {
    p = fract(p * 0.3183099) + 0.1;
    p *= p + 19.19;
    return fract(p * p);
}
float hash21(vec2 p) {
    p = fract(p * vec2(0.3183099, 0.3678794)) + 0.1;
    p += dot(p, p + 19.19);
    return fract(p.x * p.y);
}

const int bayer2x2[4] = int[4](0, 2, 3, 1);
const int bayer4x4[16] = int[16](
     0,  8,  2, 10,
    12,  4, 14,  6,
     3, 11,  1,  9,
    15,  7, 13,  5
);
const int bayer8x8[64] = int[64](
     0, 32,  8, 40,  2, 34, 10, 42,
    48, 16, 56, 24, 50, 18, 58, 26,
    12, 44,  4, 36, 14, 46,  6, 38,
    60, 28, 52, 20, 62, 30, 54, 22,
     3, 35, 11, 43,  1, 33,  9, 41,
    51, 19, 59, 27, 49, 17, 57, 25,
    15, 47,  7, 39, 13, 45,  5, 37,
    63, 31, 55, 23, 61, 29, 53, 21
);

float getBayerValue(vec2 uv, int size) {
    ivec2 pos = ivec2(mod(uv, float(size)));
    int index = pos.y * size + pos.x;
    if (size == 2) return float(bayer2x2[index]) / 4.0;
    if (size == 4) return float(bayer4x4[index]) / 16.0;
    if (size == 8) return float(bayer8x8[index]) / 64.0;
    return 0.0;
}

void main() {
    float t = .5 * u_time;
    vec2 uv = gl_FragCoord.xy / u_resolution.xy;
    uv -= .5;

    float pxSize = u_pxSize;
    vec2 pxSizeUv = gl_FragCoord.xy - .5 * u_resolution;
    pxSizeUv /= pxSize;
    vec2 pixelizedUv = floor(pxSizeUv) * pxSize / u_resolution.xy;

    vec2 shape_uv = pixelizedUv;
    vec2 dithering_uv = pxSizeUv;
    vec2 ditheringNoise_uv = uv * u_resolution;

    float shape = 0.;
    if (u_shape < 1.5) {
        shape_uv *= .001;
        float n = .5 * snoise(shape_uv - vec2(0., .3 * t));
        n += .5 * snoise(2. * shape_uv + vec2(0., .32 * t));
        shape = 0.5 + 0.5 * n;
        shape = smoothstep(0.3, 0.9, shape);
    } else if (u_shape < 2.5) {
        shape_uv *= .003;
        for (float i = 1.0; i < 6.0; i++) {
            shape_uv.x += 0.6 / i * cos(i * 2.5 * shape_uv.y + t);
            shape_uv.y += 0.6 / i * cos(i * 1.5 * shape_uv.x + t);
        }
        shape = .15 / abs(sin(t - shape_uv.y - shape_uv.x));
        shape = smoothstep(0.02, 1., shape);
    } else if (u_shape < 3.5) {
        shape_uv *= .05;
        float stripeIdx = floor(2. * shape_uv.x / TWO_PI);
        float rand = hash11(stripeIdx * 10.);
        rand = sign(rand - .5) * pow(.1 + abs(rand), .4);
        shape = sin(shape_uv.x) * cos(shape_uv.y - 5. * rand * t);
        shape = pow(abs(shape), 6.);
    } else if (u_shape < 4.5) {
        // wave — render only the line itself as a dithered band so bg is solid both above & below
        shape_uv *= 4.;
        float wave = u_waveAmp * cos(.5 * shape_uv.x - 2. * t) * sin(1.5 * shape_uv.x + t) * (.75 + .25 * cos(3. * t));
        float d = shape_uv.y + wave;
        shape = 1. - smoothstep(0.15, u_bandWidth, abs(d));
    } else if (u_shape < 5.5) {
        float dist = length(shape_uv);
        shape = sin(pow(dist, 1.7) * 7. - 3. * t) * .5 + .5;
    } else if (u_shape < 6.5) {
        float l = length(shape_uv);
        float angle = 6. * atan(shape_uv.y, shape_uv.x) + 4. * t;
        float twist = 1.2;
        float offset = pow(l, -twist) + angle / TWO_PI;
        float mid = smoothstep(0., 1., pow(l, twist));
        shape = mix(0., fract(offset), mid);
    } else {
        shape_uv *= 2.;
        float d = 1. - pow(length(shape_uv), 2.);
        vec3 pos = vec3(shape_uv, sqrt(d));
        vec3 lightPos = normalize(vec3(cos(1.5 * t), .8, sin(1.25 * t)));
        shape = .5 + .5 * dot(lightPos, pos);
        shape *= step(0., d);
    }

    int type = int(floor(u_type));
    float dithering = 0.0;
    if (type == 1) dithering = step(hash21(ditheringNoise_uv), shape);
    else if (type == 2) dithering = getBayerValue(dithering_uv, 2);
    else if (type == 3) dithering = getBayerValue(dithering_uv, 4);
    else dithering = getBayerValue(dithering_uv, 8);

    dithering -= .5;
    float res = step(.5, shape + dithering);

    vec3 fgColor = u_colorFront.rgb * u_colorFront.a;
    float fgOpacity = u_colorFront.a;
    vec3 bgColor = u_colorBack.rgb * u_colorBack.a;
    float bgOpacity = u_colorBack.a;

    vec3 color = fgColor * res;
    float opacity = fgOpacity * res;
    color += bgColor * (1. - opacity);
    opacity += bgOpacity * (1. - opacity);

    fragColor = vec4(color, opacity);
}
`;

function hexToRgba(hex: string): [number, number, number, number] {
    const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    if (!m) return [0, 0, 0, 1];
    return [
        parseInt(m[1], 16) / 255,
        parseInt(m[2], 16) / 255,
        parseInt(m[3], 16) / 255,
        1,
    ];
}

function compile(gl: WebGL2RenderingContext, type: number, src: string): WebGLShader | null {
    const sh = gl.createShader(type);
    if (!sh) return null;
    gl.shaderSource(sh, src);
    gl.compileShader(sh);
    if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        console.error('shader compile failed:', gl.getShaderInfoLog(sh));
        gl.deleteShader(sh);
        return null;
    }
    return sh;
}

function link(gl: WebGL2RenderingContext, vs: string, fs: string): WebGLProgram | null {
    const v = compile(gl, gl.VERTEX_SHADER, vs);
    const f = compile(gl, gl.FRAGMENT_SHADER, fs);
    if (!v || !f) return null;
    const p = gl.createProgram();
    if (!p) return null;
    gl.attachShader(p, v);
    gl.attachShader(p, f);
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
        console.error('program link failed:', gl.getProgramInfoLog(p));
        gl.deleteProgram(p);
        return null;
    }
    return p;
}

export function initDitheringShader(opts: DitheringOptions): DitheringHandle {
    const {
        canvas, colorBack, colorFront,
        shape = 'wave', type = '8x8',
    } = opts;

    const params: DitheringParams = {
        speed: opts.params?.speed ?? 0.6,
        pxSize: opts.params?.pxSize ?? 3,
        waveAmp: opts.params?.waveAmp ?? 1.0,
        bandWidth: opts.params?.bandWidth ?? 1.4,
    };

    const noop = { params, destroy: () => {} };

    const gl = canvas.getContext('webgl2', { antialias: false, premultipliedAlpha: true });
    if (!gl) {
        canvas.style.background = colorBack;
        return noop;
    }

    const program = link(gl, vertexShaderSource, fragmentShaderSource);
    if (!program) return noop;

    const uTime = gl.getUniformLocation(program, 'u_time');
    const uRes = gl.getUniformLocation(program, 'u_resolution');
    const uColorBack = gl.getUniformLocation(program, 'u_colorBack');
    const uColorFront = gl.getUniformLocation(program, 'u_colorFront');
    const uShape = gl.getUniformLocation(program, 'u_shape');
    const uType = gl.getUniformLocation(program, 'u_type');
    const uPxSize = gl.getUniformLocation(program, 'u_pxSize');
    const uWaveAmp = gl.getUniformLocation(program, 'u_waveAmp');
    const uBandWidth = gl.getUniformLocation(program, 'u_bandWidth');

    const posLoc = gl.getAttribLocation(program, 'a_position');
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

    const colorBackRgba = hexToRgba(colorBack);
    const colorFrontRgba = hexToRgba(colorFront);

    const resize = () => {
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        const w = Math.max(1, Math.floor(canvas.clientWidth * dpr));
        const h = Math.max(1, Math.floor(canvas.clientHeight * dpr));
        if (canvas.width !== w || canvas.height !== h) {
            canvas.width = w;
            canvas.height = h;
            gl.viewport(0, 0, w, h);
        }
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    let running = true;
    let paused = false;
    let accumulated = 0;
    let lastFrame = performance.now();

    const io = new IntersectionObserver((entries) => {
        for (const e of entries) paused = !e.isIntersecting;
    });
    io.observe(canvas);

    const render = () => {
        if (!running) return;
        const now = performance.now();
        const dt = (now - lastFrame) / 1000;
        lastFrame = now;
        if (!paused) {
            accumulated += dt * params.speed;
            gl.useProgram(program);
            gl.uniform1f(uTime, accumulated);
            gl.uniform2f(uRes, canvas.width, canvas.height);
            gl.uniform4fv(uColorBack, colorBackRgba);
            gl.uniform4fv(uColorFront, colorFrontRgba);
            gl.uniform1f(uShape, DitheringShapes[shape]);
            gl.uniform1f(uType, DitheringTypes[type]);
            gl.uniform1f(uPxSize, Math.max(1, params.pxSize));
            gl.uniform1f(uWaveAmp, params.waveAmp);
            gl.uniform1f(uBandWidth, Math.max(0.2, params.bandWidth));
            gl.drawArrays(gl.TRIANGLES, 0, 6);
        }
        requestAnimationFrame(render);
    };
    requestAnimationFrame(render);

    return {
        params,
        destroy: () => {
            running = false;
            ro.disconnect();
            io.disconnect();
            gl.deleteProgram(program);
            if (buf) gl.deleteBuffer(buf);
        },
    };
}
