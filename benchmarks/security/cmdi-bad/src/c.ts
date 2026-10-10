import { exec } from "child_process";
export function thumb(req: any) { exec("convert " + req.body.path + " out.png"); }
