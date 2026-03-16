// ml_predict.js
const { spawn } = require("child_process");

function predict(urlFeatures){
  return new Promise((resolve) => {
    const py = spawn("python", ["predict.py", JSON.stringify(urlFeatures)]);

    py.stdout.on("data", (data) => {
      resolve(data.toString());
    });
  });
}