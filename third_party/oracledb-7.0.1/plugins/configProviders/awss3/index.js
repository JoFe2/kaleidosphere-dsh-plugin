// Copyright (c) 2026, Oracle and/or its affiliates.
//-----------------------------------------------------------------------------
//
// This software is dual-licensed to you under the Universal Permissive License
// (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl and Apache License
// 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose
// either license.
//
// If you elect to accept the software under the Apache License, Version 2.0,
// the following applies:
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//-----------------------------------------------------------------------------

"use strict";

const util = require("node:util");
const { base } = require("../base.js");
const {
  createAwsCredential,
  initAwsCommon,
  initAwsRequestHandler,
  resolveRegion
} = require("../awsCommon.js");
const oracledb = require("oracledb");

let S3Client, GetObjectCommand;

class AWSS3Provider extends base {
  constructor(provider_arg, urlExtendedPart) {
    super(urlExtendedPart);
    const url = new URL(provider_arg);
    this._addParam("bucket", url.hostname);
    this._addParam("key", url.pathname.substring(1));
  }

  init() {
    initAwsCommon();
    ({ S3Client, GetObjectCommand } = require("@aws-sdk/client-s3"));
    this.requestHandler = initAwsRequestHandler(this.paramMap);
  }

  async dataFromStream(stream) {
    const chunks = [];
    return await new Promise((resolve, reject) => {
      stream.on("data", (chunk) => chunks.push(chunk));
      stream.on("end", () => {
        try {
          const data = Buffer.concat(chunks).toString("utf-8");
          resolve(data);
        } catch (error) {
          reject(new Error(`Rejected with error: ${error.message}`));
        }
      });
      stream.on("error", (error) => {
        reject(new Error(`Stream error: ${error.message}`));
      });
    });
  };

  async returnConfig() {
    const fetchRegion = await resolveRegion(this.paramMap);

    this.credential = createAwsCredential(
      this.paramMap,
      this.requestHandler,
      fetchRegion
    );

    const s3Client = new S3Client({
      region: fetchRegion,
      credentials: this.credential,
      requestHandler: this.requestHandler,
    });

    const params = {
      Bucket: this.paramMap.get("bucket"),
      Key: this.paramMap.get("key"),
    };

    try {
      const cmd = new GetObjectCommand(params);
      const resp = await s3Client.send(cmd);

      if (!resp.Body) {
        throw new Error(`S3 response body is empty for key: ${params.Key}`);
      }

      const data = await this.dataFromStream(resp.Body);
      return JSON.parse(data);
    } catch (e) {
      const errmsg = util.format(
        "Failed to retrieve or parse config: %s\n%s",
        e.message,
        e.stack
      );
      throw new Error(errmsg);
    } finally {
      s3Client.destroy();
    }
  }
}

module.exports = AWSS3Provider;

async function hookFn(args) {
  const configProvider = new AWSS3Provider(
    args.provider_arg,
    args.urlExtendedPart
  );
  try {
    configProvider.init();
  } catch (err) {
    const errmsg = util.format(
      "AWS Config Provider failed to load required modules: %s\n%s",
      err.message,
      err.stack
    );
    throw new Error(errmsg);
  }

  const cfg = await configProvider.returnConfig();
  // Return config object
  return [cfg, null];
}

oracledb.registerConfigurationProviderHook("awss3", hookFn);
