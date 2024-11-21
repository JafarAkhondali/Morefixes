# MoreFixes
MoreFixes: A Large-Scale Dataset of CVE Fix Commits Mined through Enhanced Repository Discovery
Published in Proceedings of the 20th International Conference on Predictive Models and Data Analytics in Software Engineering(2024)

Download the Source code(version used in the camera-ready paper):
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.11110595.svg)](https://doi.org/10.5281/zenodo.11110595)

Download the dataset and patches(to simply restore the dump 2024-09-26):
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.13983082.svg)](https://doi.org/10.5281/zenodo.13983082)




Paper link:
https://dl.acm.org/doi/abs/10.1145/3663533.3664036

If you find this repository useful, please consider giving a star ⭐ and please cite as:
```
@inproceedings{akhoundali2024morefixes,
  title={MoreFixes: A Large-Scale Dataset of CVE Fix Commits Mined through Enhanced Repository Discovery},
  author={Akhoundali, Jafar and Nouri, Sajad Rahim and Rietveld, Kristian and Gadyatskaya, Olga},
  booktitle={Proceedings of the 20th International Conference on Predictive Models and Data Analytics in Software Engineering},
  pages={42--51},
  year={2024}
}
```

> [!NOTE]  
> Please use the the database dump for now instead of running the whole project, there seem to be some minor issues when running the project.


## Requirements
The tool was developed and tested on Linux and macOS. **Windows is NOT SUPPORTED**. To run it, you'll need `python3.10+`, `docker`, and `docker-compose`.  
Depending on the hardware and due to rate limits(even with API keys), the tool will require several days to complete the processing.
It's highly recommended to use the provided dataset dump instead of running it from scratch. You can load the database dump, and if required, you can run the tool again to get the latest results.  
If you need to just use the database without running the code, jump to the section(Run docker containers).  


### Restore dataset dump

By default, The tool will try to load the dump file, named `postgrescvedumper-2024-09-26.sql`. You can download this file(zipped) from Zenodo: [https://zenodo.org/records/13983082](https://zenodo.org/records/13983082)
In the database(see `docker-compose.yml`). With this, you'll restore the database in a docker container. If you don't want to run the tool, you can simply use the database.
Default user credentials in the dump:
```
POSTGRES_USER=postgrescvedumper
POSTGRES_DB=postgrescvedumper
POSTGRES_PASSWORD=a42a18537d74c3b7e584c769152c3d
```


### Run docker containers
Run docker containers in MoreFixes root path by running `sudo docker-compose up -d` 

### Example usage
In the `Examples` directory, you can find a jupyter notebook with some examples of how to use the dataset.  
You can also find EER information in the `Doc` directory.  
It's highly recommended to first read the MoreFixes paper and understand different tables and their usage, especially the `fixes` table. For example, in the `fixes` table, you can choose different thresholds for the `score` column increase\decrease the noise. It's also worth to mention that commits with score less than 65 are not included in the following tables: `commits`, `file_change`, and `method_change`. However, their metadata(such as hashes) are available in the `fixes` table, which allows mining them by decreasing the `score` in the environment variable and re-running the project.


This tool consists of two main components(Morefixes and Prospector) and two data sources(NVD and GSAD)
### Configure Morefixes
> [!CAUTION]
> You have to configure Prospector as well to make Morefixes work
Clone this repository by `git clone --recurse-submodules -j8  https://github.com/JafarAkhondali/Morefixes.git` and make sure submodules are cloned("Code/resources/advisory-database" must exist).
MoreFixes structure itself is based on [CVEFixes project](https://github.com/secureIT-project/CVEfixes).
Add the Github security advisory database(https://github.com/github/advisory-database) in `Code/resources/ghsd` to get the latest vulnerabilities list.
Then, create a virtual Python environment(recommended) in the repo root directory, and install dependencies:
`pip install -r requirements.txt`

Rename `env.sample` to `.env` and update the fields in `.env` and `.CVEfixes.ini` in the tool root directory,
Note that these values should be the same for similar services(for example posgtresql database credentials) related to each other.

### Configure prospector 
Update 'config.yaml' in `/prospector` path, and copy the current `.env` file to the`/prospector` directory as well.
Create a separate virtual environment in `/prospector` named `venv` and install requirements for prospector(`pip install -r requirements.txt`).
In the Prospector venv, Run
```
python -m spacy download en_core_web_sm
python -m spacy download en_core_web_lg
python -m spacy download en
```

> [!WARNING]
> If the virtual environment directory name is not 'venv', update Python executor path in `runner.sh` 

> [!WARNING]
> We are not planning to keep the prospector in this repository, this is a temporary workaround.

### Run the tool
We HIGHLY recommend to first restore the latest backup, and then run the tool to only processes new advisories. Otherwise,
**Deactivate the venv of Prospector and switch to Morefixes venv**, then run the tool by executing `bash Code/run.sh`. This will first update the GHSA dataset in `/Code/resources/advisory-database` and download the latest CPE Dictionary from NVD and starts the whole flow mentioned in Figure 1 of the paper.
Please note we don't recommend running it on a low-end device and using the published dataset should be an easier choice if you just need to work with the available data.

### Troubleshooting
One of the heaviest modules of this software is located at `Code/resources/dynamic_commit_collector.py`, which will process possible fix commits in parallel. If you need to run the software from scratch, make sure to double-check the parameters on this page to make sure your system won't break during processing.

### Issues
Please report any issues in the official repository: [https://github.com/JafarAkhondali/Morefixes/issues/new](https://github.com/JafarAkhondali/Morefixes/issues/new)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=JafarAkhondali/Morefixes&type=Date)](https://star-history.com/#JafarAkhondali/Morefixes&Date) 
