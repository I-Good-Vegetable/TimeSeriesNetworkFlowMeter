from pathlib import Path
from typing import List, Union, Iterable

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, Subset, random_split


class TsCicIds2017(Dataset):

    def __init__(
            self,
            npzList,
            npzIndexList,
            yList,
            lenList,
            compressed=False
    ):
        self.npzList = npzList
        self.npzIndexList = npzIndexList
        self.yList = yList
        self.lenList = lenList
        self.totalLen = sum(self.lenList)
        self.compressed = compressed

    def getIndex(self, index):
        """
        Get file index and relative index from absolute index
        :param index: Absolute index
        :return: File index and relative index
        """
        if index > self.totalLen:
            raise ValueError(f'Index ({index}) cannot'
                             f' be larger than all samples')
        fileIndex = None
        for fileIndex, l in enumerate(self.lenList):
            if index < l:
                break
            index -= l
        return fileIndex, index

    def __len__(self):
        return self.totalLen

    def __getitem__(self, index):
        fileIndex, index = self.getIndex(index)
        label = self.yList[fileIndex][index]
        npzIndex = self.npzIndexList[fileIndex][index]
        mat = self.npzList[fileIndex][npzIndex].item()
        if not self.compressed:
            mat = mat.toarray()
        return mat, label


def loadDatasetsFromFiles(
        csvFiles,
        npzFiles,
        labelColName,
        indexColName,
):
    yList = list()
    npzIndexList = list()
    npzList = list()
    lenList = list()
    for csvFile, npzFile in zip(csvFiles, npzFiles):
        df = pd.read_csv(
            csvFile,
            usecols=[labelColName, indexColName],
            dtype={labelColName: str, indexColName: str}
        )
        y = df[labelColName].values
        npzIndex = df[indexColName].values
        npz = np.load(npzFile, allow_pickle=True)
        assert len(df) == len(npz), f'Csv length and npz ' \
                                    f'length are not consistent'
        yList.append(y)
        npzIndexList.append(npzIndex)
        npzList.append(npz)
        lenList.append(len(df))
    return npzList, npzIndexList, yList, lenList


def getTsCicIds2017DatasetLoader(
        folder,
        csvFiles: Iterable = None,
        npzFiles: Iterable = None,
        labelColName='Label',
        indexColName='Index',
):
    def checkFiles(files: Iterable):
        for file in files:
            if not Path(file).is_file():
                raise ValueError(f'{file} is not a valid filepath')

    if csvFiles is None:
        csvFiles = [
            'Friday-WorkingHours_Index.csv',
            'Monday-WorkingHours_Index.csv',
            'Thursday-WorkingHours_Index.csv',
            'Tuesday-WorkingHours_Index.csv',
            'Wednesday-WorkingHours_Index.csv',
        ]
    if npzFiles is None:
        npzFiles = [
            'Friday-WorkingHours_Features.npz',
            'Monday-WorkingHours_Features.npz',
            'Thursday-WorkingHours_Features.npz',
            'Tuesday-WorkingHours_Features.npz',
            'Wednesday-WorkingHours_Features.npz',
        ]
    assert len(csvFiles) == len(npzFiles), f'The length of csvFiles ' \
                                           f'and npzFiles should be same'
    csvFiles = [str(Path(folder) / file) for file in csvFiles]
    npzFiles = [str(Path(folder) / file) for file in npzFiles]
    checkFiles([*csvFiles, *npzFiles])

    npzList, npzIndexList, yList, lenList = loadDatasetsFromFiles(
        csvFiles,
        npzFiles,
        labelColName,
        indexColName
    )
    dataset = TsCicIds2017(npzList, npzIndexList, yList, lenList)

    return dataset


def checkGenerator(
        seed: Union[int, torch.Generator],
        device=None
) -> torch.Generator:
    if seed is None:
        gen = torch.Generator(device)
    elif isinstance(seed, int):
        gen = torch.Generator(device).manual_seed(seed)
    elif isinstance(seed, torch.Generator):
        gen = seed
    else:
        raise TypeError(f'Seed can only be None, int, and Generator')
    return gen


def splitDataset(
        dataset: Dataset,
        testSize=0.33,
        devSize: float = None,
        rs=None,
        device=None,
) -> List[Subset]:
    dLen = len(dataset)  # type: ignore[arg-type]
    testLen = int(dLen * testSize)
    if devSize is None:
        lengths = [dLen - testLen, testLen]
    else:
        devLen = int(dLen * devSize)
        lengths = [dLen - devLen - testLen, devLen, testLen]
    return random_split(dataset, lengths, checkGenerator(rs, device))
