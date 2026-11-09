#!/usr/bin/env python3
"""Read-only APK inventory using only Python's standard library."""
import argparse, collections, hashlib, json, re, zipfile
from pathlib import Path

def u16(b, p): return int.from_bytes(b[p:p+2], "little")
def u32(b, p): return int.from_bytes(b[p:p+4], "little")
def len8(b, p):
    x=b[p]
    return ((((x & 127)<<8)|b[p+1],2) if x & 128 else (x,1))
def len16(b, p):
    x=u16(b,p)
    return ((((x & 32767)<<16)|u16(b,p+2),4) if x & 32768 else (x,2))

def parse_manifest(b):
    strings, nodes=[], []
    p=8
    while p+8 <= len(b):
        typ, hs, size=u16(b,p),u16(b,p+2),u32(b,p+4)
        if size < 8 or p+size > len(b): break
        if typ == 1:
            count, flags, start=u32(b,p+8),u32(b,p+16),u32(b,p+20)
            for i in range(count):
                q=p+start+u32(b,p+hs+i*4)
                if flags & 0x100:
                    _,n=len8(b,q); q+=n
                    nbytes,n=len8(b,q); q+=n
                    s=b[q:q+nbytes].decode("utf-8","replace")
                else:
                    nbytes,n=len16(b,q); q+=n
                    s=b[q:q+nbytes*2].decode("utf-16le","replace")
                strings.append(s)
        elif typ == 0x0102:
            name=u32(b,p+20); start=u16(b,p+24); step=u16(b,p+26); count=u16(b,p+28)
            tag=strings[name] if name < len(strings) else "?"
            attrs={}
            for i in range(count):
                q=p+16+start+i*step
                ni,raw=u32(b,q+4),u32(b,q+8)
                vt,vd=b[q+15],u32(b,q+16)
                key=strings[ni] if ni < len(strings) else "?"
                if raw != 0xffffffff and raw < len(strings): value=strings[raw]
                elif vt == 3 and vd < len(strings): value=strings[vd]
                elif vt == 0x12: value=bool(vd)
                elif vt in (0x10,0x11): value=vd
                else: value=f"type={vt:#x}, data={vd:#x}"
                attrs[key]=value
            nodes.append((tag,attrs))
        p+=size
    root=next((a for t,a in nodes if t=="manifest"),{})
    sdk=next((a for t,a in nodes if t=="uses-sdk"),{})
    app=next((a for t,a in nodes if t=="application"),{})
    permissions=sorted({a["name"] for t,a in nodes if t.startswith("uses-permission") and "name" in a})
    components=[{"type":t,**{k:a[k] for k in ("name","exported","enabled","permission","authorities") if k in a}}
                for t,a in nodes if t in ("activity","activity-alias","service","receiver","provider")]
    return {"package":root.get("package"),"version_name":root.get("versionName"),
            "version_code":root.get("versionCode"),"compile_sdk":root.get("compileSdkVersion"),
            "min_sdk":sdk.get("minSdkVersion"),"target_sdk":sdk.get("targetSdkVersion"),
            "application_class":app.get("name"),"permissions":permissions,"components":components}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("apk",type=Path)
    ap.add_argument("--out-dir",type=Path,default=Path("build"))
    args=ap.parse_args()
    h=hashlib.sha256()
    with args.apk.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    with zipfile.ZipFile(args.apk) as z:
        infos=z.infolist()
        dex=sorted(i for i in infos if re.fullmatch(r"classes([0-9]+)?[.]dex",i.filename))
        native=[i for i in infos if i.filename.startswith("lib/") and i.filename.endswith(".so")]
        assets=[i for i in infos if i.filename.startswith("assets/")]
        groups=collections.Counter("/".join(i.filename.split("/")[:2]) for i in assets)
        manifest=parse_manifest(z.read("AndroidManifest.xml"))
        content={"zip_entries":len(infos),"dex_count":len(dex),
                 "dex_total_bytes":sum(i.file_size for i in dex),
                 "dex_files":[{"name":i.filename,"size_bytes":i.file_size} for i in dex],
                 "native_library_count":len(native),
                 "native_abis":sorted({i.filename.split("/")[1] for i in native}),
                 "assets_count":len(assets),"asset_groups":dict(sorted(groups.items())),
                 "effect_data_files":sum(i.filename.startswith("assets/effects/") and i.filename.endswith(".ta") for i in assets),
                 "shader_files":sum(i.filename.startswith("assets/shaders/") for i in assets),
                 "protected_code_markers":[i.filename for i in assets if i.filename.startswith("assets/protected_by_np/")]}
    result={"apk":{"filename":args.apk.name,"size_bytes":args.apk.stat().st_size,"sha256":h.hexdigest()},
            "manifest":manifest,"contents":content}
    args.out_dir.mkdir(parents=True,exist_ok=True)
    (args.out_dir/"apk-inventory.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    m=manifest
    lines=["# APK inventory","","> Read-only inventory; does not patch the APK or bypass code protection.","",
           "## Package",f"- Package: `{m.get('package')}`",f"- Version: `{m.get('version_name')}` (code {m.get('version_code')})",
           f"- SDK: min {m.get('min_sdk')}, target {m.get('target_sdk')}, compile {m.get('compile_sdk')}",
           f"- APK SHA-256: `{h.hexdigest()}`","", "## Contents",
           f"- ZIP entries: {content['zip_entries']}",f"- DEX files: {content['dex_count']} ({content['dex_total_bytes']:,} bytes)",
           f"- Native libraries: {content['native_library_count']} ({', '.join(content['native_abis'])})",
           f"- Assets: {content['assets_count']}",f"- Effect data files: {content['effect_data_files']}",
           f"- Shader files: {content['shader_files']}",f"- Protected-code marker files: {len(content['protected_code_markers'])}","",
           "## App-owned components"]
    lines += [f"- `{c['type']}`: `{c.get('name')}`" for c in manifest["components"] if c.get("name","").startswith("com.alightcreative")]
    lines += ["","## Notes","The package manifest identifies this as the Alight Motion Android package. Inventory alone cannot establish which differences are unique to the Doge Editing distribution. Protected-code markers are recorded but not bypassed.",""]
    (args.out_dir/"apk-inventory.md").write_text("\n".join(lines),encoding="utf-8")
    print(json.dumps({"package":m.get("package"),"version":m.get("version_name"),
                      "dex_count":content["dex_count"],"assets_count":content["assets_count"]},indent=2))

if __name__=="__main__": main()
