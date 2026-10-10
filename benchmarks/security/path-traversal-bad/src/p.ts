import fs from "fs";
export function read(req: any, res: any) { fs.readFile("/srv/files/" + req.params.name, (e, d) => res.send(d)); }
