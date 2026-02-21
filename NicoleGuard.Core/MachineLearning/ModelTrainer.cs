using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.ML;
using NicoleGuard.Core.Services;

namespace NicoleGuard.Core.MachineLearning
{
    public class ModelTrainer
    {
        private readonly string _dataFolder;
        private readonly LogService _log;
        private readonly string _trainingDataPath;
        public readonly string ModelPath;

        public ModelTrainer(string dataFolder, LogService log)
        {
            _dataFolder = dataFolder;
            _log = log;
            _trainingDataPath = Path.Combine(_dataFolder, "training_data.csv");
            ModelPath = Path.Combine(_dataFolder, "malware_model.zip");
        }

        public bool EnsureModelExists()
        {
            try
            {
                if (!File.Exists(ModelPath))
                {
                    _log.Info("ML.NET Model not found. Generating training data and training new model...");
                    GenerateDummyDataset();
                    TrainModel();
                }
                return true;
            }
            catch (Exception ex)
            {
                _log.Error($"Failed to initialize ML Model: {ex.Message}");
                return false;
            }
        }

        private void GenerateDummyDataset()
        {
            var lines = new List<string> { "FileSizeMB,Entropy,IsExecutable,ContainsHiddenAttributes,IsMalicious" };
            
            var rand = new Random();

            // Generate 1000 safe files (Low entropy, reasonable size)
            for (int i = 0; i < 1000; i++)
            {
                float size = (float)(rand.NextDouble() * 50); // 0-50MB
                float entropy = (float)(rand.NextDouble() * 5 + 1); // 1.0 - 6.0 entropy
                float isExe = rand.NextDouble() > 0.8 ? 1f : 0f; // 20% are executables
                float hidden = 0f;
                lines.Add($"{size},{entropy},{isExe},{hidden},false");
            }

            // Generate 1000 malicious files (High entropy, packed executables, hidden files)
            for (int i = 0; i < 1000; i++)
            {
                float size = (float)(rand.NextDouble() * 10); // 0-10MB (malware is usually small)
                float entropy = (float)(rand.NextDouble() * 1.5 + 7.0); // 7.0 - 8.5 entropy (packed/encrypted)
                float isExe = rand.NextDouble() > 0.1 ? 1f : 0f; // 90% are executables
                float hidden = rand.NextDouble() > 0.5 ? 1f : 0f; // 50% are hidden
                lines.Add($"{size},{entropy},{isExe},{hidden},true");
            }

            File.WriteAllLines(_trainingDataPath, lines);
            _log.Info($"Generated {lines.Count - 1} rows of training data at {_trainingDataPath}");
        }

        private void TrainModel()
        {
            var mlContext = new MLContext(seed: 0); // Seed for deterministic results

            // 1. Load Data
            IDataView dataView = mlContext.Data.LoadFromTextFile<FileFeatures>(
                path: _trainingDataPath,
                hasHeader: true,
                separatorChar: ',');

            // 2. Define data preparation pipeline
            var pipeline = mlContext.Transforms.Concatenate("Features", 
                    nameof(FileFeatures.FileSizeMB), 
                    nameof(FileFeatures.Entropy), 
                    nameof(FileFeatures.IsExecutable),
                    nameof(FileFeatures.ContainsHiddenAttributes))
                .Append(mlContext.BinaryClassification.Trainers.SdcaLogisticRegression(labelColumnName: nameof(FileFeatures.IsMalicious), featureColumnName: "Features"));

            // 3. Train Model
            _log.Info("Training ML.NET Binary Classification Model...");
            var trainedModel = pipeline.Fit(dataView);

            // 4. Evaluate Model (Optional, but good for logging)
            var predictions = trainedModel.Transform(dataView);
            var metrics = mlContext.BinaryClassification.Evaluate(predictions, labelColumnName: nameof(FileFeatures.IsMalicious));
            _log.Info($"Model Evaluation: Accuracy: {metrics.Accuracy:P2}, AUC: {metrics.AreaUnderRocCurve:P2}, F1 Score: {metrics.F1Score:P2}");

            // 5. Save Model
            mlContext.Model.Save(trainedModel, dataView.Schema, ModelPath);
            _log.Info($"Saved Trained Model to {ModelPath}");
        }
    }
}
