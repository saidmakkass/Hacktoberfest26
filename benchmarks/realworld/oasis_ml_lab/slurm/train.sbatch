#!/bin/bash
#SBATCH --job-name=oasis
#SBATCH --partition=gpu
export WANDB_API_KEY=7c1e4f9a2b8d3e6f0a1b2c3d4e5f6a7b8c9d0e1f
export DATA_HOST=gpu-node03.hpc.um6p.ma
srun python train.py --data /scratch/oasis/sensors.csv
